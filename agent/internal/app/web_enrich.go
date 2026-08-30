package app

import (
	"log/slog"
	"strings"

	"github.com/Faris-stuck/zaqorincore/agent/internal/event"
	"github.com/Faris-stuck/zaqorincore/agent/pkg/webtail"
)

// enrichWithWebParser takes an event and, if the event source
// is one we know how to parse, attaches structured metadata to
// the event by running the appropriate webtail parser on the
// raw line.
//
// The function is best-effort: if the parser does not recognise
// the line, the event is returned unchanged (so noise from
// logrotate, heartbeats, and unrelated lines do not break the
// fan-in path). Failures are logged at debug level so operators
// can investigate but the agent keeps running.
//
// Why a separate function and not inlined in Run? Because tests
// for the fan-in path want to exercise enrichment in isolation
// without bringing up the full transport.
func enrichWithWebParser(ev *event.Event, logger *slog.Logger) {
	if ev == nil {
		return
	}
	// We only have access to the raw text via the Raw field.
	// If the raw is empty (e.g. a push-mode event that already
	// has structured metadata), leave it alone.
	raw := ev.Raw
	if raw == "" {
		return
	}

	switch ev.Source {
	case event.SourceNginxAccess:
		fields, ok, err := webtail.ParseNginxLine(raw)
		if err != nil {
			logger.Debug("app: nginx parser error",
				slog.String("event_id", ev.ID),
				slog.String("error", err.Error()))
			return
		}
		if !ok {
			// Unrecognised line — likely a heartbeat or a
			// custom log_format the parser does not know.
			// Leave the event raw so the server can decide.
			logger.Debug("app: nginx parser did not recognise line",
				slog.String("event_id", ev.ID))
			return
		}
		if ev.Metadata == nil {
			ev.Metadata = make(map[string]string, len(fields))
		}
		for k, v := range fields {
			ev.Metadata[k] = v
		}

	case event.SourceModSecAudit:
		// ModSecurity audit logs are multi-line and section-based.
		// A single event corresponds to one line of the audit log
		// (a section marker, a header, or a value). The server-side
		// correlator groups lines by request id when it needs to.
		section, fields, _, ok := webtail.ParseModSecLine(raw)
		if !ok {
			logger.Debug("app: modsec parser error",
				slog.String("event_id", ev.ID))
			_ = section
			return
		}
		if fields == nil && section == "" {
			return
		}
		if ev.Metadata == nil {
			ev.Metadata = make(map[string]string, 4)
		}
		if section != "" {
			ev.Metadata["modsec_section"] = section
		}
		for k, v := range fields {
			ev.Metadata[k] = v
		}

	default:
		// Not a web source — nothing to enrich.
		_ = strings.TrimSpace
	}
}