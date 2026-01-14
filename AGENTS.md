# AGENTS.md instructions for /home/kevin/worktrees/file-guardian

<INSTRUCTIONS>
## CLI Tool Access

You have access to the AI Assistant CLI for managing lists, notes, artifact items, and panels. Only use these tools if asked by the user or a peer agent.

**List Commands:**

```bash
# List all lists
assistant-cli list ls

# Show list with items
assistant-cli list show --id <list-id>
assistant-cli list get --id <list-id>

# Create list
assistant-cli list create --name "My List" --description "..." --tag <tag>

# Add item to list
assistant-cli list item-add --id <list-id> --title "..." --url "..." --notes "..." --tag <tag>

# List tags
assistant-cli list tags-add --id <list-id> --tag <tag>
assistant-cli list tags-remove --id <list-id> --tag <tag>

# Item operations
assistant-cli list item-get --id <list-id> --item-id <id>
assistant-cli list item-rm --id <list-id> --item-id <id>
assistant-cli list item-move --item-id <id> --to-list <target-list-id>
assistant-cli list item-update --id <list-id> --item-id <id> --position <n>
assistant-cli list item-touch --id <list-id> --item-id <id>
assistant-cli list item-tags-add --id <list-id> --item-id <id> --tag <tag>
assistant-cli list item-tags-remove --id <list-id> --item-id <id> --tag <tag>

# Bulk operations
assistant-cli list items-bulk-complete --id <list-id> --item-id <id> --completed true
assistant-cli list items-bulk-tag --id <list-id> --item-id <id> --add-tag <tag> --remove-tag <tag>
assistant-cli list item-copy --id <source-list-id> --item-id <id> --to-list <target-list-id>
assistant-cli list item-copy --id <source-list-id> --lookup-title "Title" --to-list <target-list-id>
assistant-cli list items-bulk-move --id <list-id> --item-id <id> --to-list <target-list-id>
assistant-cli list items-bulk-copy --id <source-list-id> --item-id <id> --to-list <target-list-id>
```

**Note Commands:**

```bash
# List all notes
assistant-cli note ls

# Show note
assistant-cli note show --title "Note Title"

# Create/overwrite note
assistant-cli note write --title "Note Title" --content "..." --tag <tag>

# Append to note
assistant-cli note append --title "Note Title" --content "More content"

# Update tags/title
assistant-cli note update --title "Note Title" --add-tag <tag> --remove-tag <tag>
assistant-cli note update --title "Note Title" --rename "New Title"

# Search notes
assistant-cli note search --query "search term" --tag <tag> --limit 10
```

**Artifacts Commands:**

```bash
# List all artifact items (lists and notes)
assistant-cli artifacts ls
assistant-cli artifacts ls --type note
assistant-cli artifacts ls --type list

# Show artifact item content
assistant-cli artifacts show --type list --id <list-id>
assistant-cli artifacts show --type note --id "Note Title"
assistant-cli artifacts show --type note --id <note-id> --preview

# Open an item in the user's UI (panel id required)
assistant-cli artifacts open --type note --id "Note Title" --panel-id <panel-id>
assistant-cli artifacts open --type list --id <list-id> --panel-id <panel-id>

# Switch artifacts panel display mode (panel id required)
assistant-cli artifacts panel-mode --mode browser --panel-id <panel-id>
assistant-cli artifacts panel-mode --mode artifact --panel-id <panel-id>  # item detail mode (legacy name)
assistant-cli artifacts panel-mode --mode view --panel-id <panel-id>

# Get current artifacts panel state (panel id required)
assistant-cli artifacts panel-state --panel-id <panel-id>
```

**Panel Commands:**

```bash
# List open panels (panel IDs)
assistant-cli panel ls
assistant-cli panel ls --include-chat --include-context

# Get selected panels
assistant-cli panel selected
assistant-cli panel selected --include-context
```

**View Commands:**

```bash
# List saved views
assistant-cli view ls

# Create a saved view (name is required; panel id required)
assistant-cli view create --name "Urgent items" --query '{"tags":{"include":["urgent"]}}' --panel-id <panel-id>

# Update/rename a view
assistant-cli view update --id <view-id> --name "New name"
assistant-cli view update --id <view-id> --query '{"query":"meeting notes"}'

# Delete a view
assistant-cli view rm --id <view-id>

# Load a view into the artifacts panel (panel id required)
assistant-cli view load --id <view-id> --panel-id <panel-id>
```

**Diff Commands:**

```bash
# List diff status/tree/patch
assistant-cli diff status --session-id <session-id>
assistant-cli diff tree --session-id <session-id> --path <path>
assistant-cli diff patch --session-id <session-id> --path <path>

# Stage/unstage and branches
assistant-cli diff stage --session-id <session-id> --path <path>
assistant-cli diff unstage --session-id <session-id> --path <path>
assistant-cli diff branches --session-id <session-id>
assistant-cli diff checkout --session-id <session-id> --branch <branch-name>

# Review comments
assistant-cli diff comments --session-id <session-id>
assistant-cli diff comment-add --session-id <session-id> --path <file> --hunk-hash <hash> --body "Note"
assistant-cli diff comment-update --session-id <session-id> --id <comment-id> --status resolved
assistant-cli diff comment-delete --session-id <session-id> --id <comment-id>

# Hunk selection helpers
assistant-cli diff hunks --session-id <session-id>
assistant-cli diff hunk-get --session-id <session-id>
assistant-cli diff hunk-select --session-id <session-id> --list-index <n>
assistant-cli diff hunk-step --session-id <session-id> --direction next
```

**Agent Commands:**

```bash
# List available agents
assistant-cli agent ls

# Send message to an agent (headless, no WebSocket needed)
assistant-cli agent message <agentId> "message content" --mode sync
assistant-cli agent message <agentId> "message content" --session create
assistant-cli agent message <agentId> "message content" --webhook http://callback/url

# Set a cross-list view with filters (displays matching items from multiple lists)
assistant-cli agent view-set --query '{"tags":{"include":["urgent"]}}' --name "Urgent Items"
assistant-cli agent view-set --query '{"sources":[{"type":"list","id":"list-123"}],"tags":{"include":["work"]}}'
assistant-cli agent view-set --query '{"tags":{"include":["urgent"]}}' --name "Urgent Items" --panel-id <panel-id>

# Get current view (returns view query + matching items, or null if no view set)
assistant-cli agent view-get
assistant-cli agent view-get --limit 20 --cursor "..."
assistant-cli agent view-get --panel-id <panel-id>

# Clear the current view (switches back to browser mode)
assistant-cli agent view-clear
assistant-cli agent view-clear --panel-id <panel-id>
```

**Session Commands:**

```bash
# Send message to a specific session (headless)
assistant-cli session message <sessionId> "message content" --mode sync
assistant-cli session message <sessionId> "message content" --timeout 60
```

**View Query Format:**

The `--query` parameter accepts a JSON object with these fields:

```json
{
  "sources": [{ "type": "list", "id": "list-id" }],
  "query": "search text",
  "tags": {
    "include": ["tag1", "tag2"],
    "exclude": ["tag3"]
  },
  "where": {
    "field": "due",
    "op": "lt",
    "value": "today"
  },
  "union": [
    {
      "where": { "field": "due", "op": "between", "values": ["today", "+7d"] }
    },
    {
      "sources": [{ "type": "list", "id": "focus-list-id" }]
    }
  ],
  "sort": {
    "field": "due",
    "direction": "asc"
  }
}
```

Use `"op": "exists", "value": false` with `touched`/`reviewed` to find items that have never been touched.

**Date Macros:**

Date/datetime fields in `where` clauses support dynamic macros:

- `today`, `yesterday`, `tomorrow` - relative dates
- `+Nd`, `-Nd` - N days from today (e.g., `+7d`, `-3d`)
- `now` - current datetime (datetime fields) or today's date (date fields)

String fields also support day-of-week macros (including in `values` arrays):

- `dow` - today's day name (e.g., "Sunday")
- `dow+N`, `dow-N` - day name N days from today

**Tips:**

- Always run `list ls` first to see available list IDs
- Run `agent ls` to see available agents
- Use `--help` on any command for full options
- Output is JSON; parse with `jq` if needed
- Use `artifacts open` to show a specific artifact item to the user
- Use `artifacts ls` to see all artifact items across types
- Use `panel ls` to discover open panel ids (add `--include-context` to see panel context)
- Use `agent view-set` to create cross-list filtered views (including union/OR queries via the "union" array)
- Use `agent message` or `session message` for headless agent interaction
- Saved views persist across server restarts; ephemeral views (via `agent view-set`) are temporary

--- project-doc ---

## Skills
These skills are discovered at startup from multiple local sources. Each entry includes a name, description, and file path so you can open the source for full instructions.
- diff: Review git diffs in the configured workspace. (file: /home/kevin/.codex/skills/diff/SKILL.md)
- files: Browse files in the configured workspace. (file: /home/kevin/.codex/skills/files/SKILL.md)
- lists: Structured lists with items, tags, and custom fields. (file: /home/kevin/.codex/skills/lists/SKILL.md)
- notes: Markdown notes with tags and search. (file: /home/kevin/.codex/skills/notes/SKILL.md)
- panels: Panel inventory and event operations. (file: /home/kevin/.codex/skills/panels/SKILL.md)
- plan: Generate a plan for how an agent should accomplish a complex coding task. Use when a user asks for a plan, and optionally when they want to save, find, read, update, or delete plan files in $CODEX_HOME/plans (default ~/.codex/plans). (file: /home/kevin/.codex/skills/.system/plan/SKILL.md)
- skill-creator: Guide for creating effective skills. This skill should be used when users want to create a new skill (or update an existing skill) that extends Codex's capabilities with specialized knowledge, workflows, or tool integrations. (file: /home/kevin/.codex/skills/.system/skill-creator/SKILL.md)
- skill-installer: Install Codex skills into $CODEX_HOME/skills from a curated list or a GitHub repo path. Use when a user asks to list installable skills, install a curated skill, or install a skill from another repo (including private repos). (file: /home/kevin/.codex/skills/.system/skill-installer/SKILL.md)
- time-tracker: Track time against tasks with timers and manual entries. (file: /home/kevin/.codex/skills/time-tracker/SKILL.md)
- url-fetch: Fetch and extract content from external URLs. (file: /home/kevin/.codex/skills/url-fetch/SKILL.md)
- Discovery: Available skills are listed in project docs and may also appear in a runtime "## Skills" section (name + description + file path). These are the sources of truth; skill bodies live on disk at the listed paths.
- Trigger rules: If the user names a skill (with `$SkillName` or plain text) OR the task clearly matches a skill's description, you must use that skill for that turn. Multiple mentions mean use them all. Do not carry skills across turns unless re-mentioned.
- Missing/blocked: If a named skill isn't in the list or the path can't be read, say so briefly and continue with the best fallback.
- How to use a skill (progressive disclosure):
  1) After deciding to use a skill, open its `SKILL.md`. Read only enough to follow the workflow.
  2) If `SKILL.md` points to extra folders such as `references/`, load only the specific files needed for the request; don't bulk-load everything.
  3) If `scripts/` exist, prefer running or patching them instead of retyping large code blocks.
  4) If `assets/` or templates exist, reuse them instead of recreating from scratch.
- Description as trigger: The YAML `description` in `SKILL.md` is the primary trigger signal; rely on it to decide applicability. If unsure, ask a brief clarification before proceeding.
- Coordination and sequencing:
  - If multiple skills apply, choose the minimal set that covers the request and state the order you'll use them.
  - Announce which skill(s) you're using and why (one short line). If you skip an obvious skill, say why.
- Context hygiene:
  - Keep context small: summarize long sections instead of pasting them; only load extra files when needed.
  - Avoid deeply nested references; prefer one-hop files explicitly linked from `SKILL.md`.
  - When variants exist (frameworks, providers, domains), pick only the relevant reference file(s) and note that choice.
- Safety and fallback: If a skill can't be applied cleanly (missing files, unclear instructions), state the issue, pick the next-best approach, and continue.
</INSTRUCTIONS>
