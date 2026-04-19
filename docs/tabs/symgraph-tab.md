# SymGraph Tab Reference

The SymGraph tab lets you compare the current program against SymGraph, import shared analysis, and publish your own names, graph data, and document chats back to the service.

## Purpose

SymGraph is the collaboration tab in GhidrAssist. It works from the active program's SHA256 and gives you one place to:

- Check whether the current binary already exists in SymGraph
- Review remote revisions and raw-binary storage status
- Import symbols, graph data, and documents from another revision
- Publish your current symbols, graph data, and documents as a new revision

## Before You Start

- Configure the SymGraph URL and API key in [Settings](settings-tab.md). In GhidrAssist, missing-key errors point to `Settings > General > SymGraph`.
- `Refresh` works without an API key. `Upload Binary`, `Import From SymGraph`, and `Publish To SymGraph` require one.
- `Upload Binary` stores the raw binary bytes only. A publish will also upload the binary automatically if SymGraph does not already have it.

## Overview

The top of the tab has two status panels:

- **Local Status** shows the program name, SHA256, and a short local summary.
- **Remote Status** shows whether SymGraph knows about this SHA256, plus:
  - symbol, function, graph-node, and graph-edge counts
  - last-updated timestamp
  - latest revision
  - accessible revisions
  - whether the raw binary is already stored

Controls in the remote status panel:

- **Auto-refresh** re-runs the lookup when the active program changes.
- **Refresh** queries SymGraph for the current SHA256.
- **Upload Binary** pushes the raw binary bytes without publishing symbols.
- **Open in SymGraph** opens the matching binary in the SymGraph web UI once a lookup succeeds.

## Import From SymGraph

Use **Import From SymGraph** when you want to review remote changes before applying them locally.

### Configure the preview

- Choose a **Source Revision**. `Latest` is available by default, and accessible revisions are populated after `Refresh`.
- Choose which symbol classes to import: **Functions**, **Variables**, **Types**, and **Comments**.
- Enable **Include Graph Data** if you also want the remote semantic graph.
- Expand **Advanced Filters** for:
  - **Name Filter**
  - **Min Confidence**
  - **Graph Merge** policy: `Upsert`, `Prefer Local`, or `Replace`

### Review the preview

Click **Preview Import** to fetch a preview. The results are split across three tabs:

- **Changes** shows symbol rows with address, type/storage, local name, remote name, and status.
- **Documents** shows remote documents by title, size, date, and version.
- **Graph** summarizes any remote graph payload.

The changes table supports:

- `New`, `Conflicts`, and `Unchanged` filters
- `Select All`, `Deselect All`, `Select New`, `Select Conflicts`, and `Invert`
- `Apply Recommended` for a fast-path import of all `New` symbols
- `Apply Selected` for checked symbol rows plus checked documents

### Apply the import

- **Apply Recommended** imports all `New` symbols and any loaded graph preview.
- **Apply Selected** imports the checked symbol rows, checked documents, and any loaded graph preview.
- Imported documents are fetched from SymGraph and inserted into the Query history as SymGraph-backed document chats.

Graph merge policies:

- **Upsert** adds or updates imported graph nodes and edges.
- **Prefer Local** keeps existing local graph nodes when the same address already exists locally.
- **Replace** clears the local graph for this binary before importing the remote graph.

If you only want symbols or documents, rerun the preview with **Include Graph Data** turned off. Once a graph preview is loaded, apply actions include it.

## Publish To SymGraph

Use **Publish To SymGraph** to stage a revision before sending it to SymGraph.

### Configure the publish

- Choose **Scope**:
  - **Current Function** publishes the current function and related local data.
  - **Full Binary** publishes across the full program.
- Choose **Visibility**:
  - **Public**
  - **Private** if your account tier allows it
- Choose which data classes to include: **Functions**, **Variables**, **Types**, **Comments**, and optionally **Include Graph Data**.
- Expand **Advanced Filters** for a **Name Filter**.

### Review the staged publish

Click **Preview Publish** to build the outgoing set. The preview is split across:

- **Symbols** with row-level selection
- **Documents** with row-level selection and document type selection
- **Graph** with a summary of the graph payload

Supported document types are:

- `General`
- `Malware Report`
- `Vulnerability Analysis`
- `API Documentation`
- `Notes`

### Publish the selection

Click **Publish Selected** to create the revision. GhidrAssist will:

- upload the raw binary first if SymGraph does not already have it
- create a new binary revision
- push the selected symbols
- push the graph payload if it was included in the preview
- push the selected documents

If a private publish is rejected by account limits, GhidrAssist offers a retry as `Public`.

If you do not want to publish graph data, rerun the preview with **Include Graph Data** disabled. The graph preview is published as part of execution when it is loaded.

## Document Workflow

SymGraph document sync is tied to the Query experience:

- Publish previews include local document chats that are marked as SymGraph push candidates.
- You can change the outgoing document type before publishing.
- Imported documents become local SymGraph-backed chats so they can be reopened and updated later.

## Common Outcomes

- **Not found in SymGraph** means the current SHA256 has no matching remote binary yet.
- **Stored Binary: No** means SymGraph knows the binary record, but not the raw binary bytes.
- **No symbols found** can still be accompanied by graph data or documents.
- **No new symbols to apply** means the preview contained only conflicts, unchanged rows, or non-symbol data.

## Related Documentation

- [Settings Tab](settings-tab.md)
- [Semantic Graph Tab](semantic-graph-tab.md)
- [Query Tab](query-tab.md)
