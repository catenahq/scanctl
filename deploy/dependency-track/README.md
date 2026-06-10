# Dependency-Track (P3 SBOM portfolio)

scanctl generates a CycloneDX SBOM with syft and uploads it to Dependency-Track,
which owns license **policy**, continuous OSV monitoring, and the cross-project
portfolio view (the half DefectDojo does not cover).

## Run it

Dependency-Track ships an official compose (apiserver + frontend + postgres):

```sh
curl -L -O https://dependencytrack.org/docker-compose.yml
docker compose up -d
# frontend on :8080, API on :8081 by default
```

Create an API key under Administration -> Access Management -> Teams (the
"Automation" team's key, with BOM_UPLOAD + PROJECT_CREATION_UPLOAD permissions).

## Point scanctl at it

`scanctl.yml`:

```yaml
upload:
  dependency_track:
    url: https://deptrack.internal
    project_name: catena-ce
    project_version: main
```

```sh
export DEPENDENCYTRACK_APIKEY=...
scanctl run .                 # generates + uploads the SBOM
scanctl run --sbom sbom.cdx.json .   # also write it locally
```

`autoCreate` builds the project on first upload; later uploads version it and
trigger DT's monitoring. Missing key -> upload skipped with a warning.
