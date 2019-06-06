#include <PVX_Network.h>
#include <PVX_Encode.h>
#include <sstream>
#include <PVX_StdString.h>
#include <PVX.inl>
#include <zlib.h>
#include <PVX_Deflate.h>
#include <PVX_Regex.h>

namespace PVX {
	namespace Network {
		HttpClient::HttpClient() : headers{
			{"accept", L"*/*" },
			{"user-agent", L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36" },
			{"accept-encoding", L"deflate" }
		} {}



		int Chuncked(TcpSocket & Socket, std::vector<unsigned char> & data) {
			int rez = -1;
			if (!data.size()) {
				while ((rez = Socket.Receive(data)) >= 0);
				if (rez < 0) {
					data.clear();
					return 3;
				}
			}
			std::vector<unsigned char> ret;
			for (;;) {
				unsigned int ChunckSize = 0;
				int i;
				for (i = 1; i < data.size(); i++) {
					int c = i - 1;
					if (data[c] >= '0' &&  data[c] <= '9')
						ChunckSize = (ChunckSize << 4) | (data[c] - '0');
					else if (data[c] >= 'a' && data[c] <= 'f')
						ChunckSize = (ChunckSize << 4) | (data[c] - 'a' + 10);
					else if (data[c] >= 'A' && data[c] <= 'F')
						ChunckSize = (ChunckSize << 4) | (data[c] - 'A' + 10);
					else if (data[c] == '\r' && data[i] == '\n') {
						break;
					} else
						return 1;
				}
				if (!ChunckSize) {
					data = ret;
					return 0;
				}
				int h = i + 1;
				while (data.size() < (h + ChunckSize + 2) && (rez=Socket.Receive(data)) > 0);
				if (rez < 0 || data[h + ChunckSize]!='\r' || data[h + ChunckSize +1] != '\n') {
					data.clear();
					return 2;
				}
				auto lsz = ret.size();
				ret.resize(lsz + ChunckSize);
				memcpy(&ret[lsz], &data[h], ChunckSize);
				h += ChunckSize + 2;
				for (i = h; i < data.size(); i++) {
					data[i - h] = data[i];
				}
				data.resize(data.size() - h);
			}
		}
		int Chuncked(TcpSocket & Socket, std::vector<unsigned char> & data, std::function<void(const std::vector<unsigned char>&)> onReceiveData) {
			int rez;
			if (!data.size()) {
				while ((rez = Socket.Receive(data)) >= 0);
				if (rez < 0) {
					data.clear();
					return 3;
				}
			}
			onReceiveData(data);
			std::vector<unsigned char> ret;
			std::vector<unsigned char> tmpData;
			for (;;) {
				unsigned int ChunckSize = 0;
				int i;
				for (i = 1; i < data.size(); i++) {
					int c = i - 1;
					if (data[c] >= '0' &&  data[c] <= '9')
						ChunckSize = (ChunckSize << 4) | (data[c] - '0');
					else if (data[c] >= 'a' && data[c] <= 'f')
						ChunckSize = (ChunckSize << 4) | (data[c] - 'a' + 10);
					else if (data[c] >= 'A' && data[c] <= 'F')
						ChunckSize = (ChunckSize << 4) | (data[c] - 'A' + 10);
					else if (data[c] == '\r' && data[i] == '\n') {
						break;
					} else
						return 1;
				}
				if (!ChunckSize) {
					data = ret;
					return 0;
				}
				int h = i + 1;
				while (data.size() < (h + ChunckSize + 2) && (rez = Socket.Receive(tmpData)) > 0) {
					onReceiveData(tmpData);
					auto tsz = data.size();
					data.resize(tsz + tmpData.size());
					memcpy(&data[tsz], tmpData.data(), tmpData.size());
					tmpData.clear();
				}
				if (rez < 0 || data[h + ChunckSize] != '\r' || data[h + ChunckSize + 1] != '\n') {
					data.clear();
					return 2;
				}
				auto lsz = ret.size();
				ret.resize(lsz + ChunckSize);
				memcpy(&ret[lsz], &data[h], ChunckSize);
				h += ChunckSize + 2;
				for (i = h; i < data.size(); i++) {
					data[i - h] = data[i];
				}
				data.resize(data.size() - h);
			}
		}

		HttpClient::HttpResponse HttpClient::Get() {
			HttpClient::HttpResponse ret;
			TcpSocket Socket;
			auto Header = MakeHeader("GET");

			if (Socket.Connect(domain.c_str(), port.c_str())) {
				ret.StatusCode = 404;
				return ret;
			}
			if (Socket.Send(PVX::Encode::UTF(Header))) {
				Receive(Socket, ret.Headers, ret.Data, ret.Protocol, ret.StatusCode);
			}
			return ret;
		}
		HttpClient::HttpResponse HttpClient::Post(const std::wstring & Data) {
			return Post(PVX::Encode::UTF(Data));
		}

		JSON::Item HttpClient::HttpResponse::Json() {
			return JSON::parse(Data);
		}
		std::vector<unsigned char> HttpClient::HttpResponse::Raw() {
			return Data;
		}
		std::string HttpClient::HttpResponse::Text() {
			std::string ret;
			ret.resize(Data.size());
			memcpy(&ret[0], &Data[0], Data.size());
			return ret;
		}
		std::wstring HttpClient::HttpResponse::UtfText() {
			return PVX::Decode::UTF(Data);
		}

		HttpClient::HttpResponse HttpClient::Post(const std::vector<unsigned char> & Data) {
			HttpClient::HttpResponse ret;
			TcpSocket Socket;
			wchar_t buff[128];
			if (Data.size()) {
				_ui64tow_s(Data.size(), buff, 128, 10);
				headers["content-length"] = buff;
			}
			auto Header = MakeHeader("POST");

			if (Socket.Connect(domain.c_str(), port.c_str())) {
				ret.StatusCode = 404;
				return ret;
			}
			if (Socket.Send(PVX::Encode::UTF(Header))) {
				if (Data.size()) if (!Socket.Send(Data)) return ret;
				Receive(Socket, ret.Headers, ret.Data, ret.Protocol, ret.StatusCode);
			}
			return ret;
		}
		HttpClient::HttpResponse HttpClient::Post(const JSON::Item & Data) {
			headers["content-type"] = L"application/json";
			return Post(JSON::stringify(Data));
		}

		static std::wregex url_regex1(LR"__((https?)://([^/\?]+)(?:([^\?]+))?(?:\?(.*))?)__", std::regex_constants::optimize);
		static std::wregex url_regex2(LR"__(/([^\?/]*))__", std::regex_constants::optimize);
		static std::wregex url_regex3(LR"__(([^\=\&]+)(?:\=([^\&]*))?\&?)__", std::regex_constants::optimize);

		HttpClient & HttpClient::Url(const std::wstring & src) {
			using namespace PVX::Encode;
			auto url = regex_match(src, url_regex1);
			std::wstring path = url[3];
			std::wstring query = url[4];
			auto Path = regex_matches(path, url_regex2);
			auto Query = regex_matches(query, url_regex3);

			std::string src2 = ToString(url[1]) + "://" + ToString(url[2]);
			for (auto & p : Path) src2 += "/" + Uri(p[1].str());
			if (Query.size()) {
				src2 += "?";
				for (auto & q : Query) {
					src2 += Uri(q[1].str());
					if (q[2].matched) src2 += "=" + Uri(q[2].str());
				}
			}

			return Url(src2);
		}

		HttpClient & HttpClient::Url(const std::string & src) {
			protocol = src.substr(0, src.find("://"));

			for (auto & c : protocol)
				c &= ~('a'^'A');

			if (protocol == "HTTP")
				port = "80";
			else
				port = "443";

			auto psz = protocol.size() + 3;
			auto l = src.find("/", psz);
			if (l == std::string::npos) l = src.length();
			domain = src.substr(psz, l - psz);
			
			auto colon = domain.find(':');
			if (colon != std::string::npos) {
				port = domain.substr(colon + 1);
				domain.resize(colon);
				domain.shrink_to_fit();
			}

			query = src.substr(l);
			return *this;
		}

		HttpClient & HttpClient::OnReceiveHeader(std::function<void(const std::wstring&)> fnc) {
			onReceiveHeader = fnc;
			return *this;
		}

		HttpClient & HttpClient::OnReceiveData(std::function<void(const std::vector<unsigned char>&)> fnc) {
			onReceiveData = fnc;
			return *this;
		}

		std::wstring HttpClient::MakeHeader(const char * Verb) {
			using namespace PVX::Encode;
			std::wstringstream ret;

			ret << ToString((std::stringstream() << Verb << " " << query << " " << protocol << "/1.1\r\n" << "Host: " << domain << "\r\n").str());
			for (auto & h : headers) {
				ret << ToString(h.first) << L": " << h.second() << L"\r\n";
			}
			ret << L"\r\n";
			return ret.str();
		}

		std::wstring ToLower(const std::wstring & s) {
			std::wstring ret;
			ret.resize(s.size());
			std::transform(s.begin(), s.end(), ret.begin(), [](wchar_t c) { return c | ('a'^'A'); });
			return ret;
		}
		void ToLowerInplace(std::wstring & s) {
			std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return c | ('a'^'A'); });
		}

		int HttpClient::Receive(PVX::Network::TcpSocket & Socket, std::vector<SimpleTuple> & Headers, std::vector<unsigned char> & Data, std::wstring & Proto, int & Status) {
			using namespace PVX;
			using namespace PVX::String;
			std::wstring Header;
			while (Socket.Receive(Data) > 0) {
				for (auto i = 3; i < Data.size(); i++) {
					if (Data[i - 3] == '\r' && Data[i - 2] == '\n' && Data[i - 1] == '\r' && Data[i] == '\n') {
						i++;
						Header = PVX::Decode::UTF(Data.data(), i);
						for (int j = i; j < Data.size(); j++) {
							Data[j - i] = Data[j];
						}
						Data.resize(Data.size() - i);
						break;
					}
				}
				if (Header.size()) break;
			}
			
			{
				if (onReceiveHeader != nullptr) onReceiveHeader(Header);
				auto Lines = Split_No_Empties_Trimed(Header, L"\r\n");
				Proto = Lines[0].substr(0, Lines[0].find(L'/'));
				Status = _wtoi(Lines[0].substr(Lines[0].find(L' ')).c_str());

				Headers.resize(Lines.size() - 1);
				//std::transform(Lines._Make_iterator_offset(1), Lines.end(), Headers.begin(), [](const std::wstring & line) {
				std::transform(Lines.begin() + 1, Lines.end(), Headers.begin(), [](const std::wstring & line) {
					auto ar = Split_No_Empties_Trimed(line, L":");
					ToLowerInplace(ar[0]);
					return SimpleTuple{ ar[0], ar[1] };
				});
			}
			size_t ContentLenght = 0;
			int IsChunked = 0;
			int IsDeflated = 0;

			for (auto & h : Headers) {
				if (h.Name == L"transfer-encoding") {
					auto h2 = ToLower(h.Value);
					if (h2.find(L"deflate") != std::wstring::npos) 
						IsDeflated = 1;
					if (h2.find(L"chunked") != std::wstring::npos) 
						IsChunked = 1;
				} else if (h.Name == L"content-length") {
					ContentLenght = _wtoi64(h.Value.c_str());
				} else if (h.Name == L"set-cookie") {
					auto c = Split_No_Empties_Trimed(h.Value, L";");
					auto cookie = Split_Trimed(c[0], L"=");
					Cookies[cookie[0]] = cookie[1];
				}
			}
			int rez = 0;
			if (IsChunked) {
				if(onReceiveData!=nullptr)
					rez = Chuncked(Socket, Data, onReceiveData);
				else
					rez = Chuncked(Socket, Data);
			} else {
				if (onReceiveData != nullptr) {
					if (Data.size()) onReceiveData(Data);
					std::vector<unsigned char> tmpData;
					while (Data.size() < ContentLenght && (rez = Socket.Receive(tmpData)) > 0) {
						onReceiveData(tmpData);
						auto sz = Data.size();
						Data.resize(sz + tmpData.size());
						memcpy(&Data[sz], tmpData.data(), tmpData.size());
						tmpData.clear();
					}
				} else {
					while (Data.size() < ContentLenght && (rez = Socket.Receive(Data)) > 0);
				}
			}
			if (!Data.size()) return 1;

			if (IsDeflated) {
				Data = PVX::Compress::Inflate(Data);
			}

			return 0;
		}


		HttpClient::HttpResponse::HttpResponse() {

		}
	}
}