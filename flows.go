package main

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
)

// Flow is one OS-observed network connection from agentsnitch, normalized for
// the replay overlay. It is a THIRD evidence layer: the flow itself is a fact
// (a real socket the OS saw), but the link to a tool call is agentsnitch's
// probabilistic correlation — carried with its confidence, never as our verdict.
type Flow struct {
	TS         string `json:"ts"`                   // UTC — aligns to the chain timeline
	Host       string `json:"host"`                 // best hostname/SNI, else remote
	Remote     string `json:"remote,omitempty"`     // ip:port
	Direction  string `json:"direction,omitempty"`  // out | in
	PID        int    `json:"pid,omitempty"`
	BytesOut   int64  `json:"bytes_out,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	LinkedTool string `json:"linked_tool,omitempty"` // agentsnitch's associated tool-use id
	Confidence string `json:"confidence,omitempty"`  // agentsnitch's link confidence (low/med/high)
	Why        string `json:"why,omitempty"`         // agentsnitch's summary of WHY it linked (their claim)
	Observer   string `json:"observer,omitempty"`    // sensor path (network_statistics / lsof / ...)
}

// agentsnitch envelope: {"schema":"...transcript.v0","kind":"correlated|network","event":{...}}
type asnEnvelope struct {
	Kind  string          `json:"kind"`
	Event json.RawMessage `json:"event"`
}

type asnFlowEvent struct {
	TS        string `json:"ts"`
	Remote    string `json:"remote"`
	Host      string `json:"hostname"`
	SNI       string `json:"sni"`
	PTR       string `json:"ptr_hostname"`
	Direction string `json:"direction"`
	PID       int    `json:"pid"`
	BytesOut  int64  `json:"bytes_out"`
	Protocol  string `json:"protocol"`
	Observer  string `json:"observer"`
}

type asnCorrelated struct {
	TS          string         `json:"ts"`
	Confidence  string         `json:"confidence"`
	Summary     string         `json:"summary"`
	SemanticIDs []string       `json:"semantic_ids"`
	Flows       []asnFlowEvent `json:"flows"`
}

func bestHost(f asnFlowEvent) string {
	for _, h := range []string{f.SNI, f.Host, f.PTR} {
		if h = strings.TrimSpace(h); h != "" {
			return h
		}
	}
	return f.Remote
}

// loadFlows parses an agentsnitch session events.jsonl into a deduped, time-
// ordered list of outbound-relevant flows. Correlated events carry the tool
// link + confidence; bare network events are facts with no link.
func loadFlows(path string) ([]Flow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[string]bool{} // dedupe identical (ts,host,dir)
	var out []Flow
	add := func(fl Flow) {
		if fl.Host == "" || fl.TS == "" {
			return
		}
		key := fl.TS + "\x00" + fl.Host + "\x00" + fl.Direction
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, fl)
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var env asnEnvelope
		if json.Unmarshal([]byte(line), &env) != nil {
			continue
		}
		switch env.Kind {
		case "correlated":
			var c asnCorrelated
			if json.Unmarshal(env.Event, &c) != nil {
				continue
			}
			tool := ""
			if len(c.SemanticIDs) > 0 {
				tool = c.SemanticIDs[0]
			}
			for _, fe := range c.Flows {
				if fe.Direction != "out" {
					continue
				}
				add(Flow{
					TS: fe.TS, Host: bestHost(fe), Remote: fe.Remote, Direction: fe.Direction,
					PID: fe.PID, BytesOut: fe.BytesOut, Protocol: fe.Protocol, Observer: fe.Observer,
					LinkedTool: tool, Confidence: c.Confidence, Why: c.Summary,
				})
			}
		case "network":
			var fe asnFlowEvent
			if json.Unmarshal(env.Event, &fe) != nil {
				continue
			}
			if fe.Direction != "out" {
				continue
			}
			add(Flow{
				TS: fe.TS, Host: bestHost(fe), Remote: fe.Remote, Direction: fe.Direction,
				PID: fe.PID, BytesOut: fe.BytesOut, Protocol: fe.Protocol, Observer: fe.Observer,
			})
		}
	}
	return out, sc.Err()
}
