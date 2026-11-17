# node_app - the Node half of the dynamic self-test fixture

**DO NOT FIX THE BUGS HERE.** See [`../py_app/README.md`](../py_app/README.md): it documents both
fixtures, the shared route table, the `/safe/*` negative controls and the seed list
(`../py_app/seeds.json`). This directory is the same routes on Node core, so one self-test plan
runs against either runtime.

```
python dynamic/probe.py      --launch work/_selftest/node_app --selftest
python dynamic/authz_diff.py --launch work/_selftest/node_app --selftest
```
