package cmd

// getAlerts test when AccountStatus always fails
// - events should not be collected
// - alertStore should not be created
// - follow should not be updated
// - there should be warning

// getAlerts test when AccountStatus always returns expired
// - events should not be collected
// - alertStore should not be created
// - follow should not be updated
// - there should be warning

// getAlerts test when AccountStatus returns always correct status,
// but Events fails
// - alertStore should not be created
// - follow should not be updated
// - there should be warning

// getAlerts happy path test
// - alertStore contain gathered alerts
// - follow should be updated
// - no warning logs

// queries test when asoc.Queries fails
// limit for files should be set to 10
// fake DNSCapture should return 100 queries
// - queries should be stored to file
// - no more than 10 files with queries

// queries test when asoc.Queries returns all rejected
//  - warning should be written
// -  no files qith queries created

// queries from local files test
// - generate 10 blocks of data
// - fail on sending
// - read them from file
// - accept from sending function
