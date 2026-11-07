1. Data extraction

- [ ] Create fixtures: one get-entries batch, one checkpoint, one data tile and its level-0 hash tile
- [ ] Query CT log lists, both RFC 6962 `logs` and static `tiled_logs` (state, temporal window, url kind)
- [ ] Decode both leaf formats and create unified entry type
- [ ] Parse certificate data from that entry (precert and final)
- [ ] Fetch static issuer certificates by fingerprint

2. Log traversal

- [ ] Backfill one frozen log first (e.g. Sectigo Mammoth2026h2), then static tiles, then the billion-entry logs
  - [ ] Query original CT API logs
  - [ ] Query new static/tiled logs
- [ ] Keep progress in Sqlite/PostgreSQL: leaf index and last tree size per log
- [ ] Tail usable logs after the backfill; a read-only log is done at its final tree size
- [ ] Store each leaf in ClickHouse (log, index, fingerprint, precert or final)
- [ ] Reconcile precerts, final certs, and exact dupes into an issuance keyed by issuer and serial
- [ ] Store domains reversed for prefix/suffix search (double check if needed)
- [ ] Rate-limit RFC 6962 fetches; identify the client on static fetches
- [ ] Properly handle retries, timeouts, scaling

3. Data interaction

- [ ] DNS twisting https://github.com/elceef/dnstwist
- [ ] Domain prefix/postfix filtering
- [ ] Simple API/websocket
- [ ] Simple UI (experiment with GPUI? or normal web UI?)

4. Historical/archived log ingestion

- [ ] Ingest retired/rejected logs if its URL still answers
- [ ] Ingest dumped archives and check them against the original signed root https://github.com/geomys/ct-archive

5. Verification

- [ ] Check static data tiles against their hash tiles and the checkpoint, and RFC 6962 row counts against tree_size
- [ ] Compare a known domain with an existing source and look for misses or bad parses
