# Packing Keys Network API Kanban

Status date: 2026-01-12

## Backlog
- Add end-to-end test covering HTTP query with packing keys enabled
- Consider binary (bincode) transport for packing keys to reduce JSON overhead
- Document payload size impact in docs/COMMUNICATION_COSTS.md

## In Progress
- None

## Done
- Serialize `ClientPackingKeys` in network payloads (compact y_body only)
- Include packing keys on seeded query types and propagate through expand()
- Use InspiRING for seeded queries when packing keys are present (server path)
- Update docs/README/CHANGELOG to reflect network support
- Default to InspiRING packing; require explicit `packing_mode=tree` for tree packing
