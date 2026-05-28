# Golden-event test fixtures

Tracked: caver-collector#75

Convention per OCSF class:
```
caver/tests/golden/<class_uid>/
  in.json    # raw input event
  out.json   # expected OCSF-normalized output
```

The test harness in `vrl-caver-stdlib` will load these fixtures and
run them through the VRL normalization functions as snapshot tests.
