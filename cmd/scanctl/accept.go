package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/catenahq/scanctl/internal/baseline"
	"github.com/catenahq/scanctl/internal/config"
	"github.com/catenahq/scanctl/internal/gate"
	"github.com/catenahq/scanctl/internal/sarif"
)

const acceptDateLayout = "2006-01-02"

// acceptCmd records the third-party image findings a run's SARIF holds that gate
// (a fixed version, at or above the floor, from a block-mode tool) in the
// committed baseline, each accepted until the -until date. An image entry that
// is live keeps its date, an expired one takes -until, a finding with no entry
// gets one, and an entry the input no longer reports is dropped when the input
// holds a run that scanned every image. Entries for the repo's own tree are left
// as they are.
func acceptCmd(args []string) int {
	fs := flag.NewFlagSet("accept", flag.ExitOnError)
	until := fs.String("until", "", "")
	cfgPath := fs.String("config", "scanctl.yml", "")
	baselinePath := fs.String("baseline", ".scanctl/baseline.sarif", "")
	_ = fs.Parse(args)

	now := time.Now()
	end, err := time.Parse(acceptDateLayout, *until)
	if err != nil || end.Format(acceptDateLayout) <= now.UTC().Format(acceptDateLayout) {
		fmt.Fprintf(os.Stderr, "accept: -until must be a date after today (YYYY-MM-DD), got %q\n", *until)
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "accept: want one SARIF path")
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 2
	}
	in, err := sarif.Load(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "accept:", err)
		return 2
	}
	existing, err := baseline.LoadReport(*baselinePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "baseline:", err)
		return 2
	}
	if existing == nil {
		existing = sarif.New()
	}

	out, counts := acceptImages(existing, in, cfg, *until, now)
	if err := writeBaseline(*baselinePath, out); err != nil {
		fmt.Fprintln(os.Stderr, "accept:", err)
		return 2
	}
	fmt.Printf("accept: %d added, %d renewed, %d removed, %d kept in %s\n",
		counts.added, counts.renewed, counts.removed, counts.kept, *baselinePath)
	return 0
}

type acceptCounts struct{ added, renewed, removed, kept int }

// acceptImages returns the baseline existing becomes once the image findings of
// in are accepted until the given date, and what changed.
func acceptImages(existing, in *sarif.Report, cfg config.Config, until string, now time.Time) (*sarif.Report, acceptCounts) {
	var counts acceptCounts
	var selected []sarif.Result
	have := map[string]int{}
	// reported holds every image finding the input carries, selected or not: an
	// entry whose finding is still reported is not removed.
	reported := map[string]bool{}
	imagesWhole := false
	for _, run := range in.Runs {
		tool := run.Tool.Driver.Name
		if run.Category().ID == sarif.ImageCategory {
			imagesWhole = true
		}
		rules := run.RulesByID()
		for _, r := range run.Results {
			if _, ok := r.Properties[sarif.ImageProperty].(string); !ok {
				continue
			}
			reported[sarif.Fingerprint(tool, r)] = true
			if cfg.Tools[tool].Mode != config.ModeBlock {
				continue
			}
			if sarif.FixedVersion(tool, r) == "" ||
				gate.Severity(tool, rules, r).Rank() < cfg.Gate.Floor.Rank() {
				continue
			}
			sel := acceptedEntry(r, until)
			selected = append(selected, sel)
			have[sarif.Fingerprint(tool, sel)]++
		}
	}

	out := &sarif.Report{Schema: existing.Schema, Version: existing.Version, Runs: []sarif.Run{}}
	var images []sarif.Result
	matched := map[string]int{}
	for _, run := range existing.Runs {
		tool := run.Tool.Driver.Name
		kept := run
		kept.Results = nil
		stripped := false
		for _, r := range run.Results {
			if _, image := r.Properties[sarif.ImageProperty]; !image {
				kept.Results = append(kept.Results, r)
				continue
			}
			stripped = true
			fp := sarif.Fingerprint(tool, r)
			switch {
			case have[fp] > 0:
				have[fp]--
				matched[fp]++
				if baseline.Expired(r, now) {
					r = withDate(r, until)
					counts.renewed++
				} else {
					counts.kept++
				}
				images = append(images, r)
			case !imagesWhole || reported[fp]:
				counts.kept++
				images = append(images, r)
			default:
				counts.removed++
			}
		}
		if len(kept.Results) > 0 || !stripped {
			out.Runs = append(out.Runs, kept)
		}
	}
	for _, sel := range selected {
		fp := sarif.Fingerprint("trivy", sel)
		if matched[fp] > 0 {
			matched[fp]--
			continue
		}
		images = append(images, sel)
		counts.added++
	}

	sort.SliceStable(images, func(i, j int) bool {
		a, b := images[i], images[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		ia, ib := a.Properties[sarif.ImageProperty].(string), b.Properties[sarif.ImageProperty].(string)
		if ia != ib {
			return ia < ib
		}
		return a.Message.Text < b.Message.Text
	})
	if len(images) > 0 {
		out.Runs = append(out.Runs, sarif.Run{
			Tool:    sarif.Tool{Driver: sarif.Driver{Name: "trivy"}},
			Results: images,
		})
	}
	return out, counts
}

// acceptedEntry is the baseline entry for a finding: what identifies it, and
// the date it is accepted until.
func acceptedEntry(r sarif.Result, until string) sarif.Result {
	return withDate(sarif.Result{
		RuleID:     r.RuleID,
		Level:      r.Level,
		Message:    r.Message,
		Properties: map[string]any{sarif.ImageProperty: r.Properties[sarif.ImageProperty]},
	}, until)
}

// withDate returns r with its acceptedUntil property set, leaving r's own
// property map untouched.
func withDate(r sarif.Result, until string) sarif.Result {
	props := map[string]any{}
	for k, v := range r.Properties {
		props[k] = v
	}
	props[baseline.AcceptedUntil] = until
	r.Properties = props
	return r
}

func writeBaseline(path string, rep *sarif.Report) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	// #nosec G306 -- the baseline is committed to the repo; 0644 is intentional
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
