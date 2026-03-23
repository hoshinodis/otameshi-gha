package main

import rego.v1

# Helper: extract text from heading node children
_adr_heading_text(h) := concat("", [c.value | some c in h.children; c.type == "text"])

_adr_filename := object.get(input, ["metadata", "filename"], "")

# All headings
_adr_headings := [h | some h in input.children; h.type == "heading"]

# H3 names in order
_adr_h3_names := [_adr_heading_text(h) | some h in input.children; h.type == "heading"; h.depth == 3]

# Rule 3: Exactly one H1
deny contains msg if {
	_adr_filename != ""
	h1s := [h | some h in _adr_headings; h.depth == 1]
	count(h1s) != 1
	msg := sprintf("ADR must have exactly one H1, found %d", [count(h1s)])
}

# Rule 4: Exactly one H2
deny contains msg if {
	_adr_filename != ""
	h2s := [h | some h in _adr_headings; h.depth == 2]
	count(h2s) != 1
	msg := sprintf("ADR must have exactly one H2, found %d", [count(h2s)])
}

# Rule 5: Required H3 sections — Status, Context, Decision, Consequences
_adr_required_h3s := ["Status", "Context", "Decision", "Consequences"]

deny contains msg if {
	_adr_filename != ""
	some required in _adr_required_h3s
	not required in {name | some name in _adr_h3_names}
	msg := sprintf("ADR must have '### %s' section", [required])
}

# Rule 6: Status must be one of the allowed values
# Check the first paragraph after the ## Status heading
_adr_valid_statuses := {"Accepted", "Deprecated", "Superseded"}

deny contains msg if {
	_adr_filename != ""
	"Status" in {name | some name in _adr_h3_names}
	some i, node in input.children
	node.type == "heading"
	node.depth == 3
	_adr_heading_text(node) == "Status"
	# Find the next paragraph after Status heading
	next_node := input.children[i + 1]
	next_node.type == "paragraph"
	status_text := concat("", [c.value | some c in next_node.children; c.type == "text"])
	not status_text in _adr_valid_statuses
	msg := sprintf("ADR Status must be one of {Proposed, Accepted, Deprecated, Superseded}, got: '%s'", [status_text])
}