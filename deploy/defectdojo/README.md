# DefectDojo (P2 aggregation plane)

scanctl uploads its merged SARIF to DefectDojo via the import-scan API. This is
the single findings dashboard: dedup, triage, trends across every tool and repo.

## Run it

DefectDojo ships an official multi-service compose (django + postgres + redis +
celery worker/beat + nginx). Do not vendor a fork of it -- track upstream:

```sh
git clone https://github.com/DefectDojo/django-DefectDojo
cd django-DefectDojo
./dc-up.sh postgres-redis           # or: docker compose up -d
docker compose logs initializer | grep "Admin password"
```

Then create an API v2 token (User menu -> API v2 Key) and point scanctl at it.

## Point scanctl at it

`scanctl.yml`:

```yaml
upload:
  defectdojo:
    url: https://defectdojo.internal
    product_name: catena
    engagement_name: catena-ce
```

Credential is an env var, never committed:

```sh
export DEFECTDOJO_TOKEN=...           # User -> API v2 Key
scanctl run .
```

`auto_create_context=true` means the product + engagement are created on the
first import; subsequent runs reimport and dedup. If `DEFECTDOJO_TOKEN` is unset
the upload is skipped with a warning -- a missing dashboard never fails a scan.
