#ifndef __PVX_ENCODE_H__
#define __PVX_ENCODE_H__

#include<vector>
#include<string>
#include<array>

namespace PVX{
	namespace Encode{
		std::string ToString(const std::vector<unsigned char> & data);
		std::string ToString(const std::wstring & data);
		std::wstring ToString(const std::string & data);
		std::string Base64(const void * data, int size);
		std::string Base64(const std::vector<unsigned char> & data);
		std::vector<unsigned char> UTF0(const std::wstring & Text);
		std::vector<unsigned char> UTF(const std::wstring & Text);
		void UTF(std::vector<unsigned char> & utf, const std::wstring & Text);
		int UTF(unsigned char * Data, const wchar_t * Str);
		int UTF_Length(const wchar_t * Str);
		int UTF_Length(const std::wstring & Str);
		int Uri_Length(const char * u);
		std::string UriEncode(const std::string & s);
		std::string UriEncode(const std::vector<unsigned char> & s);
		std::string Uri(const std::wstring & s);
		std::string Windows1253_Greek(const std::wstring & data);


		std::array<unsigned char, 20> SHA1(const void * msg, size_t sz);
	}
	namespace Decode{
		std::vector<unsigned char> Base64(const std::string & base64);
		std::vector<unsigned char> Base64(const std::wstring & base64);
		std::string Base64_String(const std::string & base64);

		std::wstring UTF(const unsigned char * utf, int sz);
		std::wstring UTF(const std::vector<unsigned char> & Utf);
		wchar_t * pUTF(const unsigned char * utf);
		std::wstring Windows1253(const std::vector<unsigned char> & s);
		std::wstring Windows1253(const char * s);
		std::wstring Uri(const std::string & s);
		std::wstring Uri(const std::wstring & s);
		std::wstring Unescape(const std::wstring& x);
	}
}

#endif