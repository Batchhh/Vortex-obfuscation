## What does this PR do?

<!-- One or two sentences. Link the related issue if there is one. Closes #<issue> -->

## Changes

<!-- Brief bullet list of what changed and why -->

-

## Checklist

- [ ] Builds cleanly on Linux and macOS (`make CC=gcc` / `make CC=clang`)
- [ ] `make debug` (OBF_DISABLE) still compiles without warnings
- [ ] `strings example | grep -Ei "hello|secret|bearer"` produces no output
- [ ] No heap allocations introduced; stack-only
- [ ] C11 compatible — no compiler extensions that don't have a fallback
- [ ] Relevant headers/docs updated if the public API changed

## Testing done

<!-- What did you run to verify this? Paste relevant output. -->
