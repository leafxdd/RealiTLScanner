package data

import _ "embed"

//go:embed data/cdn_keywords.txt
var EmbeddedCDNKeywords []byte

//go:embed data/hot_websites.txt
var EmbeddedHotWebsites []byte
