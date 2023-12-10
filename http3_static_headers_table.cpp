#include <unordered_map>

#include "http3_static_headers_table.hpp"


namespace neosystem {
namespace http3 {

static std::unordered_map<uint32_t, neosystem::http::header> g_table;


void init_http3_static_headers_table(void) {
	if (!g_table.empty()) {
		return;
	}

	g_table[0] = {":authority", ""};
	g_table[1] = {":path", "/"};
	g_table[2] = {"age", "0"};
	g_table[3] = {"content-disposition", ""};
	g_table[4] = {"content-length", "0"};
	g_table[5] = {"cookie", ""};
	g_table[6] = {"date", ""};
	g_table[7] = {"etag", ""};
	g_table[8] = {"if-modified-since", ""};
	g_table[9] = {"if-none-match", ""};
	g_table[10] = {"last-modified", ""};
	g_table[11] = {"link", ""};
	g_table[12] = {"location", ""};
	g_table[13] = {"referer", ""};
	g_table[14] = {"set-cookie", ""};
	g_table[15] = {":method", "CONNECT"};
	g_table[16] = {":method", "DELETE"};
	g_table[17] = {":method", "GET"};
	g_table[18] = {":method", "HEAD"};
	g_table[19] = {":method", "OPTIONS"};
	g_table[20] = {":method", "POST"};
	g_table[21] = {":method", "PUT"};
	g_table[22] = {":scheme", "http"};
	g_table[23] = {":scheme", "https"};
	g_table[24] = {":status", "103"};
	g_table[25] = {":status", "200"};
	g_table[26] = {":status", "304"};
	g_table[27] = {":status", "404"};
	g_table[28] = {":status", "503"};
	g_table[29] = {"accept", "*/*"};
	g_table[30] = {"accept", "application/dns-message"};
	g_table[31] = {"accept-encoding", "gzip, deflate, br"};
	g_table[32] = {"accept-ranges", "bytes"};
	g_table[33] = {"access-control-allow-headers", "cache-control"};
	g_table[34] = {"access-control-allow-headers", "content-type"};
	g_table[35] = {"access-control-allow-origin", "*"};
	g_table[36] = {"cache-control", "max-age=0"};
	g_table[37] = {"cache-control", "max-age=2592000"};
	g_table[38] = {"cache-control", "max-age=604800"};
	g_table[39] = {"cache-control", "no-cache"};
	g_table[40] = {"cache-control", "no-store"};
	g_table[41] = {"cache-control", "public, max-age=31536000"};
	g_table[42] = {"content-encoding", "br"};
	g_table[43] = {"content-encoding", "gzip"};
	g_table[44] = {"content-type", "application/dns-message"};
	g_table[45] = {"content-type", "application/javascript"};
	g_table[46] = {"content-type", "application/json"};
	g_table[47] = {"content-type", "application/x-www-form-urlencoded"};
	g_table[48] = {"content-type", "image/gif"};
	g_table[49] = {"content-type", "image/jpeg"};
	g_table[50] = {"content-type", "image/png"};
	g_table[51] = {"content-type", "text/css"};
	g_table[52] = {"content-type", "text/html;charset=utf-8"};
	g_table[53] = {"content-type", "text/plain"};
	g_table[54] = {"content-type", "text/plain;charset=utf-8"};
	g_table[55] = {"range", "bytes=0-"};
	g_table[56] = {"strict-transport-security", "max-age=31536000"};
	g_table[57] = {"strict-transport-security", "max-age=31536000;includesubdomains"};
	g_table[58] = {"strict-transport-security", "max-age=31536000;includesubdomains;preload"};
	g_table[59] = {"vary", "accept-encoding"};
	g_table[60] = {"vary", "origin"};
	g_table[61] = {"x-content-type-options", "nosniff"};
	g_table[62] = {"x-xss-protection", "1; mode=block"};
	g_table[63] = {":status", "100"};
	g_table[64] = {":status", "204"};
	g_table[65] = {":status", "206"};
	g_table[66] = {":status", "302"};
	g_table[67] = {":status", "400"};
	g_table[68] = {":status", "403"};
	g_table[69] = {":status", "421"};
	g_table[70] = {":status", "425"};
	g_table[71] = {":status", "500"};
	g_table[72] = {"accept-language", ""};
	g_table[73] = {"access-control-allow-credentials", "FALSE"};
	g_table[74] = {"access-control-allow-credentials", "TRUE"};
	g_table[75] = {"access-control-allow-headers", "*"};
	g_table[76] = {"access-control-allow-methods", "get"};
	g_table[77] = {"access-control-allow-methods", "get, post, options"};
	g_table[78] = {"access-control-allow-methods", "options"};
	g_table[79] = {"access-control-expose-headers", "content-length"};
	g_table[80] = {"access-control-request-headers", "content-type"};
	g_table[81] = {"access-control-request-method", "get"};
	g_table[82] = {"access-control-request-method", "post"};
	g_table[83] = {"alt-svc", "clear"};
	g_table[84] = {"authorization", ""};
	g_table[85] = {"content-security-policy", "script-src 'none';object-src 'none';base-uri 'none'"};
	g_table[86] = {"early-data", "1"};
	g_table[87] = {"expect-ct", ""};
	g_table[88] = {"forwarded", ""};
	g_table[89] = {"if-range", ""};
	g_table[90] = {"origin", ""};
	g_table[91] = {"purpose", "prefetch"};
	g_table[92] = {"server", ""};
	g_table[93] = {"timing-allow-origin", "*"};
	g_table[94] = {"upgrade-insecure-requests", "1"};
	g_table[95] = {"user-agent", ""};
	g_table[96] = {"x-forwarded-for", ""};
	g_table[97] = {"x-frame-options", "deny"};
	g_table[98] = {"x-frame-options", "sameorigin"};
	return;
}

const neosystem::http::header *find_http3_static_headers_table(uint32_t key) {
	auto it = g_table.find(key);
	if (it == g_table.end()) {
		return nullptr;
	}
	return &(it->second);
}

std::size_t get_http3_static_headers_table_size(void) {
	return g_table.size();
}

}
}
