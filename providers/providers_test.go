package providers

import (
	"testing"
	"time"

	"github.com/jonhadfield/ipscout/session"

	"github.com/stretchr/testify/require"
)

// portAgeCheck returns true if the port is within the max age
// func portAgeCheck(portConfirmedTime string, timeFormat string, maxAge string) (bool, error) {
// 	// if no age filter provided, then return false
// 	if maxAge == "" {
// 		return false, nil
// 	}
//
// 	var confirmedTime time.Time
// 	var err error
//
// 	maxAgeHours, err := AgeToHours(maxAge)
// 	if err != nil {
// 		return false, fmt.Errorf("error parsing max-age: %w", err)
// 	}
//
// 	confirmedTime, err = time.Parse(timeFormat, portConfirmedTime)
// 	if err != nil {
// 		return false, err
// 	}
//
// 	if confirmedTime.Before(time.Now().Add(-time.Duration(maxAgeHours) * time.Hour)) {
// 		return true, err
// 	}
//
// 	return false, nil
// }

func TestPortAgeCheckWithNoValues(t *testing.T) {
	res, err := portAgeCheck("", "", "")
	require.Error(t, err)
	require.False(t, res)
}

func TestPortAgeCheckNoMaxAge(t *testing.T) {
	res, err := portAgeCheck("2024-04-04 00:00:00", time.DateTime, "")
	require.NoError(t, err)
	require.True(t, res)
}

func TestPortAgeCheckOlderThanMaxAge(t *testing.T) {
	res, err := portAgeCheck("2024-04-01 00:00:00", time.DateTime, "1d")
	require.NoError(t, err)
	require.False(t, res)
}

func TestPortMatchFilterWithNoValues(t *testing.T) {
	ageMatch, netMatch, err := PortMatchFilter(PortMatchFilterInput{
		IncomingPort:        "",
		MatchPorts:          nil,
		ConfirmedDate:       "",
		ConfirmedDateFormat: "",
		MaxAge:              "",
	})
	require.NoError(t, err)
	require.True(t, ageMatch)
	require.True(t, netMatch)
}

func TestPortMatchFilterWithNetworkMatch(t *testing.T) {
	age, res, err := PortMatchFilter(PortMatchFilterInput{
		IncomingPort:        "80",
		MatchPorts:          []string{"90/udp", "80"},
		ConfirmedDate:       "2006-01-02 15:04:05",
		ConfirmedDateFormat: time.DateTime,
		MaxAge:              "8h",
	})
	require.NoError(t, err)
	require.True(t, res)
	require.False(t, age)
}

func TestPortMatchFilterWithNegativeNetworkMatch(t *testing.T) {
	age, res, err := PortMatchFilter(PortMatchFilterInput{
		IncomingPort:        "80",
		MatchPorts:          []string{"800"},
		ConfirmedDate:       "2024-01-02 15:04:05",
		ConfirmedDateFormat: time.DateTime,
		MaxAge:              "10000w",
	})
	require.NoError(t, err)
	require.False(t, res)
	require.True(t, age)
}

func TestPortMatchFilterWithDateAndNoMaxAge(t *testing.T) {
	_, res, err := PortMatchFilter(PortMatchFilterInput{
		IncomingPort:        "80",
		MatchPorts:          []string{"800"},
		ConfirmedDate:       "2006-01-02 15:04:05",
		ConfirmedDateFormat: time.DateTime,
		MaxAge:              "",
	})
	// PortMatch will only attempt to match age if provided,
	// so this does not constitute an error despite providing confirmed date and format
	require.NoError(t, err)
	// returns false as no port match and no age match attempted
	require.False(t, res)
}

func TestPortMatchFilterWithNegativeNetworkMatchPositiveDateMatch(t *testing.T) {
	_, res, err := PortMatchFilter(PortMatchFilterInput{
		IncomingPort:        "80",
		MatchPorts:          []string{"800"},
		ConfirmedDate:       "2006-01-02 15:04:05",
		ConfirmedDateFormat: time.DateTime,
		MaxAge:              "",
	})
	require.NoError(t, err)
	require.False(t, res)
}

func TestDashIfEmptyWithString(t *testing.T) {
	empty := ""
	notEmpty := "test"

	require.Equal(t, "-", DashIfEmpty(empty))
	require.Equal(t, "-", DashIfEmpty(&empty))
	require.Equal(t, "test", DashIfEmpty(notEmpty))
	require.Equal(t, "test", DashIfEmpty(&notEmpty))
}

func TestDashIfEmptyWithInt(t *testing.T) {
	empty := 0
	notEmpty := 1

	require.Equal(t, "0", DashIfEmpty(empty))
	require.Equal(t, "1", DashIfEmpty(notEmpty))
}

func TestDashIfEmptyWithTime(t *testing.T) {
	require.Equal(t, "-", DashIfEmpty(time.Time{}))
	require.Equal(t, "2024-04-19 19:00:00 UTC", DashIfEmpty(time.Date(2024, time.April, 19, 19, 0, 0, 0, time.UTC)))
}

func TestPreProcessValueOutput(t *testing.T) {
	require.Equal(t, "test", PreProcessValueOutput(&session.Session{Config: session.Config{Global: session.GlobalConfig{MaxValueChars: 0}}}, "test"))
	require.Equal(t, "test", PreProcessValueOutput(&session.Session{Config: session.Config{Global: session.GlobalConfig{MaxValueChars: 4}}}, "test"))
	require.Equal(t, "test...", PreProcessValueOutput(&session.Session{Config: session.Config{Global: session.GlobalConfig{MaxValueChars: 4}}}, "testing"))
}

func TestPortMatchFilterWithPortMatchOnly(t *testing.T) {
	ageMatch, netMatch, err := PortMatchFilter(PortMatchFilterInput{
		IncomingPort:        "80/tcp",
		MatchPorts:          []string{"tcp"},
		ConfirmedDate:       "",
		ConfirmedDateFormat: "",
		MaxAge:              "",
	})
	require.NoError(t, err)
	require.True(t, ageMatch)
	require.True(t, netMatch)
}

func TestPortNetworkMatchWithoutPortsSpecified(t *testing.T) {
	var ports []string

	require.True(t, PortNetworkMatch("80", ports))
	require.True(t, PortNetworkMatch("80/udp", ports))
}

func TestPortNetworkMatch(t *testing.T) {
	ports := []string{"80", "tcp", "80/tcp"}

	require.True(t, PortNetworkMatch("80", []string{}))
	require.True(t, PortNetworkMatch("80", ports))
	require.False(t, PortNetworkMatch("800", ports))
	require.True(t, PortNetworkMatch("tcp", ports))
	require.False(t, PortNetworkMatch("udp", ports))
	require.True(t, PortNetworkMatch("80/tcp", ports))
	require.True(t, PortNetworkMatch("80/udp", ports))
}

func TestPortNetworkMatchNonWideTransport(t *testing.T) {
	ports := []string{"80", "80/tcp"}

	require.False(t, PortNetworkMatch("50/tcp", ports))
	require.True(t, PortNetworkMatch("80", []string{}))
	require.True(t, PortNetworkMatch("80", ports))
	require.False(t, PortNetworkMatch("800", ports))
	require.True(t, PortNetworkMatch("tcp", ports))
	require.False(t, PortNetworkMatch("udp", ports))
	require.True(t, PortNetworkMatch("80/tcp", ports))
	require.True(t, PortNetworkMatch("80/udp", ports))
}

func TestPortNetworkMatchNonWidePort(t *testing.T) {
	ports := []string{"tcp", "80/tcp"}
	require.True(t, PortNetworkMatch("50/tcp", ports))
	require.True(t, PortNetworkMatch("80", []string{}))
	require.True(t, PortNetworkMatch("80", ports))
	require.False(t, PortNetworkMatch("800", ports))
	require.True(t, PortNetworkMatch("tcp", ports))
	require.False(t, PortNetworkMatch("udp", ports))
	require.True(t, PortNetworkMatch("80/tcp", ports))
	require.False(t, PortNetworkMatch("80/udp", ports))
}

func TestSplitPortTransport(t *testing.T) {
	pt := splitPortTransport("80")
	require.Equal(t, "80", pt.port)
	require.Empty(t, pt.transport)

	pt = splitPortTransport("tcp")
	require.Empty(t, pt.port)
	require.Equal(t, "tcp", pt.transport)

	pt = splitPortTransport("80/tcp")
	require.Equal(t, "80", pt.port)
	require.Equal(t, "tcp", pt.transport)

	pt = splitPortTransport("80/udp")
	require.Equal(t, "80", pt.port)
	require.Equal(t, "udp", pt.transport)
}

func TestIsPort(t *testing.T) {
	require.True(t, isPort("80"))
	require.True(t, isPort("800"))
	require.False(t, isPort("80000"))
	require.False(t, isPort("tcp"))
}

func TestAgeToHours(t *testing.T) {
	h, err := AgeToHours("")
	require.NoError(t, err)
	require.Equal(t, int64(0), h)

	h, err = AgeToHours("2h")
	require.NoError(t, err)
	require.Equal(t, int64(2), h)

	h, err = AgeToHours("3d")
	require.NoError(t, err)
	require.Equal(t, int64(72), h)

	h, err = AgeToHours("1w")
	require.NoError(t, err)
	require.Equal(t, int64(168), h)

	h, err = AgeToHours("2m")
	require.NoError(t, err)
	require.Equal(t, int64(1440), h)

	h, err = AgeToHours("1y")
	require.NoError(t, err)
	require.Equal(t, int64(8760), h)

	h, err = AgeToHours("bad")
	require.Error(t, err)
	require.Equal(t, int64(0), h)
}

func TestFormatTimeOrDash(t *testing.T) {
	ts := "2024-04-19 19:00:00"
	formatted := FormatTimeOrDash(ts, time.DateTime)
	require.Equal(t, "2024-04-19 19:00:00 UTC", formatted)

	require.Equal(t, "-", FormatTimeOrDash("", time.DateTime))
	require.Equal(t, "-", FormatTimeOrDash(ts, ""))
	require.Equal(t, "-", FormatTimeOrDash("bad", time.DateTime))
}

func TestPadRight(t *testing.T) {
	require.Equal(t, "a    ", PadRight("a", 5))
	require.Equal(t, "test", PadRight("test", 4))
}

func TestUpdateScoreIfLarger(t *testing.T) {
	a := 1.0
	UpdateScoreIfLarger(&a, 2)
	require.Equal(t, 2.0, a)

	UpdateScoreIfLarger(&a, 1)
	require.Equal(t, 2.0, a)
}
