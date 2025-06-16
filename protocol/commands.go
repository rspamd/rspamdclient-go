// Package protocol contains commands that can be sent to the server
package protocol

// RspamdCommand represents commands that can be sent to the server
type RspamdCommand int

const (
	Scan RspamdCommand = iota
	LearnSpam
	LearnHam
)

// RspamdEndpoint represents an ephemeral endpoint representation
type RspamdEndpoint struct {
	URL      string
	Command  RspamdCommand
	NeedBody bool
}

// FromCommand creates a new endpoint from a command
func FromCommand(command RspamdCommand) RspamdEndpoint {
	switch command {
	case Scan:
		return RspamdEndpoint{
			URL:      "/checkv2",
			Command:  command,
			NeedBody: true,
		}
	case LearnSpam:
		return RspamdEndpoint{
			URL:      "/learnspam",
			Command:  command,
			NeedBody: true,
		}
	case LearnHam:
		return RspamdEndpoint{
			URL:      "/learnham",
			Command:  command,
			NeedBody: true,
		}
	default:
		return RspamdEndpoint{
			URL:      "/checkv2",
			Command:  Scan,
			NeedBody: true,
		}
	}
}
