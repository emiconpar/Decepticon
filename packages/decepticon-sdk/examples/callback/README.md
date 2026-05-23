# decepticon-example-callback

A Decepticon plugin (callback) scaffolded by ``decepticon-sdk plugin new``.

## Build + install

```bash
uv build
pip install dist/*.whl
```

After install, the framework's plugin loader discovers this contribution
via the ``decepticon.callbacks`` entry-point group.

## Test

```bash
pip install decepticon-sdk[testing]
pytest
```

Use ``decepticon_sdk.testing.FakeBackend`` / ``FakeLLM`` / ``FakeSandbox``
to write hermetic tests that don't need a live framework.
