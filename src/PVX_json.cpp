#include<PVX_json.h>
#include<PVX_Encode.h>
#include<sstream>
//#include<pvx_algorithm.inl>
#include<regex>
#include <PVX_Regex.h>
#include <stdio.h>

static std::wstring JsonString(const std::wstring & s) {
	std::wstringstream ret;
	ret << '"';
	for (auto c : s) {
		switch (c) {
		case '"': ret << "\\\""; break;
		case '\n': ret << "\\n"; break;
		case '\t': ret << "\\t"; break;
		case '\r': ret << "\\r"; break;
		case '\\': ret << "\\\\"; break;
		default: ret << c;
		}
	}
	ret << '"';
	return ret.str();
}

namespace PVX {
	namespace JSON {
		static void WriteNumber(FILE * f, size_t n) {
			fwrite(&n, 4, 1, f);
		}
		static void WriteString(FILE * f, const std::wstring & s) {
			WriteNumber(f, s.size());
			fwrite(&s[0], sizeof(wchar_t), s.size(), f);
		}
		void Item::WriteBin(void * f) {
			WriteNumber((FILE*)f, (size_t)Type);
			WriteNumber((FILE*)f, NumericFloat);
			switch(Type) {
			case JSON::jsElementType::Number: fwrite(&_Integer, sizeof(long long), 1, (FILE*)f); break;
			case JSON::jsElementType::String: WriteString((FILE*)f, String); break;
			case JSON::jsElementType::Array: 
				WriteNumber((FILE*)f, Array.size());
				for(auto & i : Array)
					i.WriteBin(f);
				break;
			case JSON::jsElementType::Object:
				WriteNumber((FILE*)f, Object.size());
				for(auto & i : Object) {
					if(i.second.Type!= JSON::jsElementType::Undefined && i.second.Type!=JSON::jsElementType::Null)
					WriteString((FILE*)f, i.first);
					i.second.WriteBin(f);
				}
				break;
			};
		}
		int Item::SaveBinary(const wchar_t * Filename) {
			FILE * fout;
			if(!_wfopen_s(&fout, Filename, L"wb")) {
				WriteBin(fout);
				fclose(fout);
			}
			return 0;
		}

		int Item::SaveBinary(const char * Filename) {
			FILE * fout;
			if(!fopen_s(&fout, Filename, "wb")) {
				WriteBin(fout);
				fclose(fout);
			}
			return 0;
		}
		static double ReadDouble(FILE * f) {
			double ret;
			fread(&ret, sizeof(double), 1, f);
			return ret;
		}
		static size_t ReadInt(FILE * f) {
			size_t ret = 0;
			fread(&ret, 4, 1, f);
			return ret;
		}
		static long long ReadLong(FILE * f) {
			long long ret = 0;
			fread(&ret, sizeof(long long), 1, f);
			return ret;
		}
		static std::wstring ReadString(FILE * f) {
			size_t tmp = 0;
			fread(&tmp, 4, 1, f);
			std::wstring ret;
			ret.resize(tmp);
			fread(&ret[0], sizeof(wchar_t), tmp, f);
			return ret;
		}
		Item Item::ReadBin(void * f) {
			JSON::jsElementType type = (JSON::jsElementType)ReadInt((FILE*)f);
			int IsFloat = ReadInt((FILE*)f);
			size_t count;
			switch(type) {
			case JSON::jsElementType::Number:
				if(IsFloat)	return ReadDouble((FILE*)f);
				else return ReadLong((FILE*)f);
			case JSON::jsElementType::String: 
				return ReadString((FILE*)f);
			case JSON::jsElementType::Array: 
			{ count = ReadInt((FILE*)f); Item ret = JSON::jsElementType::Array; for(auto i = 0; i < count; i++) ret.Array.push_back(ReadBin(f)); return ret; };
			case JSON::jsElementType::Object: 
			{ count = ReadInt((FILE*)f); Item ret = JSON::jsElementType::Object; for(auto i = 0; i < count; i++) { auto name = ReadString((FILE*)f); ret.Object[name] = ReadBin(f); } return ret; }; };
			return type;
		}
		Item Item::ReadBinary(const char * Filename) {
			FILE * fin;
			if(!fopen_s(&fin, Filename, "rb")) {
				return ReadBin(fin);
			}
			return jsElementType::Undefined;
		}
		Item Item::ReadBinary(const wchar_t * Filename) {
			FILE * fin;
			if(!_wfopen_s(&fin, Filename, L"rb")) {
				return ReadBin(fin);
			}
			return jsElementType::Undefined;
		}
		void Item::Release() {
			String.clear();
			Array.clear();
			Object.clear();
		}
		Item::Item() : Type{ jsElementType::Undefined }, NumericFloat{ 0 }, _Integer{0} {}
		Item::Item(const enum jsElementType& tp) : Type{ tp }, NumericFloat{ 0 }, _Integer{ 0 }{}
		Item::Item(const bool& v) : Type{ jsElementType::Boolean }, NumericFloat{ 0 }, _Integer{ v } {}
		Item::Item(const int& v) : Type{ jsElementType::Number }, NumericFloat{ 0 }, _Integer{ v } {}
		Item::Item(const enum jsBoolean& v) : Type{ jsElementType::Number }, NumericFloat{ 0 }, _Integer{ (bool)v } {}
		Item::Item(const long long& v) : Type{ jsElementType::Number }, NumericFloat{ 0 }, _Integer{ v } {}
		Item::Item(const float& v) : Type{ jsElementType::Number }, NumericFloat{ 1 }, _Double{ v } {}
		Item::Item(const double& v) : Type{ jsElementType::Number }, NumericFloat{ 1 }, _Double{ v } {}
		Item::Item(const std::wstring & s) : Type{ jsElementType::String }, NumericFloat{ 0 }, _Integer{ 0 } { String = s; }
		Item::Item(const wchar_t * s) : Type{ jsElementType::String }, NumericFloat{ 0 }, _Integer{ 0 } { String = s; }
		Item::Item(const nullptr_t&) : Type{ jsElementType::Null }, NumericFloat{ 0 }, _Integer{ 0 } {}
		Item::Item(const std::string & s) : Type{ jsElementType::String }, NumericFloat{ 0 }, _Integer{ 0 } { for (auto c : s) String.push_back(c); }
		Item::Item(const char * str) : Type{ jsElementType::String }, NumericFloat{ 0 }, _Integer{ 0 } { int i = 0; while (str[i]) String.push_back(str[i++]); }
		//Item::Item(const Item & obj) : Type{ obj.Type }, NumericFloat{ obj.NumericFloat }, _Integer{ obj._Integer }, String{ obj.String }, Object{ obj.Object }, Array{ obj.Array }{}



		static std::wstring wstr(const std::string & str) {
			std::wstring ret; ret.resize(str.size());
			memcpy(&ret[0], &str[0], str.size());
			return ret;
		}

		Item::Item(const std::initializer_list<Tuple> & its) {
			Type = JSON::jsElementType::Object;
			for (auto & it : its) {
				Object[it.Name] = it._Item;
			}
		}
		//Item::Item(const std::map<std::wstring, std::wstring> & Dictionary) {
		//	for (auto & d : Dictionary)
		//		Object[d.first] = d.second;
		//}
		//Item::Item(const std::map<std::wstring, double> & Dictionary) {
		//	for (auto & d : Dictionary)
		//		Object[d.first] = d.second;
		//}
		//Item::Item(const std::map<std::wstring, float> & Dictionary) {
		//	for (auto & d : Dictionary)
		//		Object[d.first] = d.second;
		//}
		//Item::Item(const std::map<std::wstring, int> & Dictionary) {
		//	for (auto & d : Dictionary)
		//		Object[d.first] = d.second;
		//}
		//Item::Item(const std::map<std::string, std::wstring> & Dictionary) {
		//	for (auto & d : Dictionary)
		//		Object[wstr(d.first)] = d.second;
		//}
		//Item::Item(const std::map<std::string, std::string> & Dictionary) {
		//	for (auto & d : Dictionary)
		//		Object[wstr(d.first)] = d.second;
		//}
		//Item::Item(const std::map<std::wstring, std::string> & Dictionary) {
		//	for (auto & d : Dictionary)
		//		Object[d.first] = d.second;
		//}
		//Item::Item(const std::map<std::wstring, Item> & Dictionary) {
		//	for (auto & d : Dictionary)
		//		Object[d.first] = d.second;
		//}

		Item::Item(const array & its) {
			Type = JSON::jsElementType::Array;
			for (auto & it : its.itms) {
				Array.push_back(it);
			}		
		}

		//Item::Item(const std::initializer_list<Item>& its) {
		//	Type = JSON::jsElementType::Array;
		//	for (auto & it : its) {
		//		Array.push_back(it);
		//	}
		//}

		Item::~Item() {
			Release();
		}
		Item & Item::operator=(const jsElementType tp) {
			Release();
			Type = tp;
			return *this;
		}
		Item & Item::operator=(const int v) {
			Release();
			Type = JSON::jsElementType::Number;
			_Integer = v;
			NumericFloat = 0;
			return *this;
		}
		Item & Item::operator=(const long long v) {
			Release();
			Type = JSON::jsElementType::Number;
			_Integer = v;
			NumericFloat = 0;
			return *this;
		}
		Item & Item::operator=(const float v) {
			Release();
			Type = JSON::jsElementType::Number;
			NumericFloat = 1;
			_Double = v;
			return *this;
		}
		Item & Item::operator=(const double v) {
			Release();
			Type = JSON::jsElementType::Number;
			NumericFloat = 1;
			_Double = v;
			return *this;
		}
		Item & Item::operator=(const bool v) {
			Release();
			Type = JSON::jsElementType::Boolean;
			NumericFloat = 0;
			_Integer = v;
			return *this;
		}
		Item & Item::operator=(const std::wstring & v) {
			Release();
			Type = JSON::jsElementType::String;
			String = v;
			return *this;
		}

		Item & Item::operator=(const std::string & s) {
			Release();
			Type = JSON::jsElementType::String;
			String.reserve(s.size());
			for (auto c : s) String.push_back(c);
			return *this;
		}
		Item & Item::operator=(const wchar_t * v) {
			Release();
			Type = JSON::jsElementType::String;
			String = v;
			return *this;
		}

		Item & Item::operator=(const char * s2) {
			std::string s = s2;
			Release();
			Type = JSON::jsElementType::String;
			String.reserve(s.size());
			for (auto c : s) String.push_back(c);
			return *this;
		}

		Item & Item::operator=(const std::vector<unsigned char>& v) {
			Release();
			Type = JSON::jsElementType::String;
			std::string tmp = PVX::Encode::Base64(v);
			String.reserve(tmp.size());
			for (auto c : tmp) String.push_back(c);
			return *this;
		}

		Item & Item::operator=(const Item & obj) {
			Release();
			Type = obj.Type;
			_Integer = obj._Integer;
			NumericFloat = obj.NumericFloat;
			String = obj.String;
			Object = obj.Object;
			Array = obj.Array;
			return *this;
		}

		Item & Item::operator[](const std::wstring & Name) {
			Type = jsElementType::Object;
			return Object[Name];
		}

		Item & Item::operator[](const std::string & Name) {
			Type = jsElementType::Object;
			std::wstring n;
			for (auto c : Name)n.push_back(c);
			return Object[n];
		}

		Item & Item::operator[](int Index) {
			return Array[Index];
		}

		Item Item::Get(const std::wstring& Name, const Item& Default) const {
			if (auto ret = Object.find(Name); ret!=Object.end())
				return ret->second;
			return Default;
		}

		const Item * Item::Has(const std::wstring & Name) const {
			if (auto ret = Object.find(Name); ret != Object.end())
				return &(ret->second);
			return nullptr;
		}

		Item & Item::operator<<(const std::wstring & s) {
			Release();
			*this = parse(s.c_str());
			return *this;
		}

		void Item::push(const Item & it) {
			Array.push_back(it);
		}

		Item Item::pop() {
			auto ret = Array.back();
			Array.pop_back();
			return ret;
		}

		int Item::length() {
			return (int)Array.size();
		}

		int Item::IsNull() {
			return Type == jsElementType::Null;
		}
		int Item::IsUndefined() {
			return Type == jsElementType::Undefined;
		}
		int Item::IsNullOrUndefined() {
			return Type == jsElementType::Null || Type == jsElementType::Undefined;
		}
		int Item::IsEmpty() {
			return 
				Type == jsElementType::Null ||
				Type == jsElementType::Undefined ||
				(Type == jsElementType::Number && !_Integer) ||
				(Type == jsElementType::String && !this->String.size()) ||
				(Type == jsElementType::Array && !this->Array.size()) ||
				(Type == jsElementType::Object && !this->Object.size());
		}

		std::vector<std::wstring> Item::Keys() const {
			std::vector<std::wstring> ret;
			for (auto & kv : Object)
				ret.push_back(kv.first);
			return ret;
		}
		std::vector<PVX::JSON::Item> Item::Values() const {
			std::vector<PVX::JSON::Item> ret;
			for (auto & kv : Object)
				ret.push_back(kv.second);
			return ret;
		}

		double Item::NumberSafeDouble() {
			if (Type == jsElementType::Number) {
				return NumericFloat ? _Double : (double)_Integer;
			}if (Type == jsElementType::String)
				return _wtof(this->String.c_str());
			return 0.0;
		}

		long long Item::NumberSafeInteger() {
			if (Type == jsElementType::Number) {
				return NumericFloat ? _Integer : (long long)_Double;
			}if (Type == jsElementType::String)
				return _wtoi(this->String.c_str());
			return 0.0;
		}

		std::vector<unsigned char> Item::Data() {
			return PVX::Decode::Base64(String);
		}

		std::wstring Item::GetString() {
			if (Type== jsElementType::String)
				 return String;
			return stringify(*this);
		}

		void Item::Data(const std::vector<unsigned char>& d) {
			Type = jsElementType::String;
			String = PVX::Encode::ToString(PVX::Encode::Base64(d));
		}

		Item Item::map(std::function<Item(const Item&)> Convert) {
			if (Type == JSON::jsElementType::Array) {
				Item ret = JSON::jsElementType::Array;
				for (auto & i : Array) {
					ret.Array.push_back(Convert(i));
				}
				return ret;
			}
			return jsElementType::Undefined;
		}

		Item Item::map2(std::function<Item(const Item&, int Index)> Convert) {
			if (Type == JSON::jsElementType::Array) {
				Item ret = JSON::jsElementType::Array;
				int Index = 0;
				for (auto& i : Array) {
					ret.Array.push_back(Convert(i, Index++));
				}
				return ret;
			}
			return jsElementType::Undefined;
		}

		void Item::each(std::function<void(Item&)> Func) {
			if (Type == JSON::jsElementType::Array) for (auto & i : Array) Func(i);
		}
		void Item::each2(std::function<void(Item&, int Index)> Func) {
			int Index = 0;
			if (Type == JSON::jsElementType::Array) for (auto& i : Array) Func(i, Index++);
		}
		void Item::eachInObject(std::function<void(const std::wstring& Name, Item&)> Func) {
			if (Type!=jsElementType::Object)return;
			for (auto& [Name, Value] : Object) Func(Name, Value);
		}
		Item Item::GroupBy(std::function<std::wstring(const Item&)> Func) {
			if (Type!=jsElementType::Array) return jsElementType::Undefined;
			Item ret = jsElementType::Object;
			each([&](const Item& it) {
				std::wstring Name = Func(it);
				if (!ret.Has(Name)) ret[Name] = jsElementType::Array;
				ret[Name].push(it);
			});
			return ret;
		}

		Item Item::filter(std::function<int(const Item&)> Test) {
			if (Type == JSON::jsElementType::Array) {
				Item ret = JSON::jsElementType::Array;
				for (auto & i : Array) {
					if(Test(i))
						ret.Array.push_back(i);
				}
				return ret;
			}
			return jsElementType::Undefined;
		}
		Item Item::find(std::function<int(const Item&)> Test, size_t Start){
			if (Type == JSON::jsElementType::Array) for (auto i = Start; i < Array.size(); i++) if (Test(Array[i])) return Array[i];
			return jsElementType::Undefined;
		}

		int Item::findIndex(std::function<int(const Item&)> Test, size_t Start) {
			if (Type == JSON::jsElementType::Array) for (auto i = Start; i < Array.size();i++) if (Test(Array[i])) return i;
			return -1;
		}

		Item Item::sort(std::function<int(Item&, Item&)> Compare) {
			if (Type == JSON::jsElementType::Array) {
				Item ret = Copy();
				//PVX::Algorithm::qsort<Item>(ret.Array.data(), ret.Array.size(), Compare);
				std::sort(ret.Array.begin(), ret.Array.end(), Compare);
				return ret;
			}
			return jsElementType::Undefined;
		}

		Item Item::Copy() {
			Item ret = Type;
			ret.NumericFloat = NumericFloat;
			ret._Integer = _Integer;
			ret.String = String;
			for (auto & w : Array)
				ret.Array.push_back(w);
			for (auto & w : Object)
				ret.Object[w.first] = w.second;
			return ret;
		}

		Item Item::DeepCopy() {
			Item ret = Type;
			ret.NumericFloat = NumericFloat;
			ret._Integer = _Integer;
			ret.String = String;
			for (auto & w : Array)
				ret.Array.push_back(w.DeepCopy());
			for (auto & w : Object)
				ret.Object[w.first] = w.second.DeepCopy();
			return ret;
		}
		Item Item::DeepReducedCopy() {
			Item ret = Type;
			ret.NumericFloat = NumericFloat;
			ret._Integer = _Integer;
			ret.String = String;
			int Count = 0;
			switch (Type) {
			case jsElementType::Null: return jsElementType::Undefined;
			case jsElementType::Array:
				for (auto & w : Array) {
					auto x = w.DeepReducedCopy();
					Count += x.Type == jsElementType::Undefined;
					ret.Array.push_back(x);
				}
				if(Count==Array.size()) return jsElementType::Undefined;
				return ret;
			case jsElementType::Object:
				for (auto &[Name, Value] : Object) {
					auto itm = Value.DeepReducedCopy();
					if (itm.Type != jsElementType::Undefined) {
						Count++;
						ret.Object[Name] = itm;
					}
				}
				if (Count)return ret;
				return jsElementType::Undefined;
			}
			return ret;
		}

		Item & Item::Cache() {
			return *cache;
		}

		Item & Item::Cache(const std::string & str) {
			cache = &((*this)[str]);
			return *cache;
		}

		Item & Item::Cache(const std::wstring & str) {
			cache = &((*this)[str]);
			return *cache;
		}

		Item & Item::Merge(const Item & With) {
			if(this->Type == jsElementType::Undefined) {
				(*this) = With;
				return *this;
			}
			if(this->Type == With.Type) {
				if(this->Type == JSON::jsElementType::Object) {
					for(auto & it : With.Object) 
						(*this)[it.first].Merge(it.second);
				} else if(this->Type == JSON::jsElementType::Array) {
					for(auto & it : With.Array)
						(*this).push(it);
				}
			}
			return *this;
		}

		std::wstring lvl(int l) {
			return L"\n" + std::wstring(l, L'\t');
		}
		
		std::wstring stringify(const Item& obj, int level) {
			std::wstringstream ret;
			switch (obj.Type) {
				case jsElementType::Undefined:
					return L"undefined";
				case jsElementType::Null:
					return L"null";
				case jsElementType::Number:
					if (obj.NumericFloat) {
						ret << obj.Double();
					} else {
						ret << obj.Integer();
					}
					return ret.str();
				case jsElementType::Boolean:
					return obj.Integer() ? L"true" : L"false";
				case jsElementType::String:
					return JsonString(obj.String);
				case jsElementType::Array:
					ret << "[";
					if (obj.Array.size()) {
						size_t i = 0;
						while (i< obj.Array.size() && obj.Array[i].Type==jsElementType::Undefined)i++;
						ret << lvl(level + 1) << stringify(obj.Array[i], level + 1); i++;
						while (i< obj.Array.size() && obj.Array[i].Type==jsElementType::Undefined)i++;
						for (; i < obj.Array.size(); i++) {
							ret << "," << lvl(level + 1) << stringify(obj.Array[i], level + 1);
							while (i< obj.Array.size() && obj.Array[i].Type==jsElementType::Undefined)i++;
						}
					}
					ret << lvl(level) << "]";
					return ret.str();
				case jsElementType::Object:
				{
					ret << "{";
					auto iter = obj.Object.begin();

					while (iter!=obj.Object.end() && iter->second.Type == jsElementType::Undefined) iter++;

					if (iter != obj.Object.end()) {
						ret << lvl(level + 1) << JsonString(iter->first) << ": " << stringify(iter->second, level + 1);
						++iter;
					}

					for (; iter != obj.Object.end(); ++iter) {
						if (iter->second.Type != jsElementType::Undefined)
							ret << "," << lvl(level + 1) << JsonString(iter->first) << ": " << stringify(iter->second, level + 1);
					}

					ret << lvl(level) << "}";
					return ret.str();
				}
				default:
					return L"";
			}
		}

		std::wstring stringify(const Item & obj) {
			return stringify(obj, 0);
		}

//#define ISSPACE(x) ((x)==' '||(x)=='\t'||(x)=='\n'||(x)=='\r')
//#define SKIP_SPACE(json, i) while (ISSPACE((json)[(i)]))i++;
//
//		static std::wstring parseString(const wchar_t * s, int & i) {
//			i = 0;
//			int escape = 0;
//			i++;
//			std::wstring ret;
//			for (; s[i]; i++) {
//				if (!escape && s[i] == '"') {
//					i++;
//					SKIP_SPACE(s, i);
//					return ret;
//				}
//				if (s[i] == '\\' && !escape) {
//					escape = 1;
//					continue;
//				}
//				if (escape) {
//					if (s[i] == L'n') ret.push_back(L'\n');
//					else if (s[i] == L'r') ret.push_back(L'\r');
//					else if (s[i] == L't') ret.push_back(L'\t');
//					else ret.push_back(s[i]);
//					escape = 0;
//					continue;
//				}
//				ret.push_back(s[i]);
//				escape = 0;
//			}
//			SKIP_SPACE(s, i);
//			return ret;
//		}
//		static int parseNumber(const wchar_t * s, int & i, long long & Int, double & Doub) {
//			int IsFloat = 0;
//			i += s[0] == L'-' || s[0]==L'+';
//			while(s[i] >= L'0' && s[i] <= L'9') i++;
//			if(s[i] == '.') {
//				IsFloat = 1;
//				i++;
//				while(s[i] >= L'0' && s[i] <= L'9') i++;
//			}
//			if(s[i] == L'e'|| s[i] == L'E') {
//				i++;
//				i += s[i] == L'-' || s[i] == L'+';
//				while(s[i] >= L'0' && s[i] <= L'9') i++;
//			}
//			SKIP_SPACE(s, i);
//			if (IsFloat)
//				Doub = _wtof(s);
//			else
//				Int = _wtoi(s);
//			return IsFloat;
//		}
//
//		static Item parse(const wchar_t * s, int & i) {
//			i = 0;
//			SKIP_SPACE(s, i);
//			switch (s[i]) {
//			case L'"':
//				return parseString(s, i);
//			case L'{':
//			{
//				i++;
//				Item it = jsElementType::Object;
//				SKIP_SPACE(s, i);
//				while (s[i] != L'}') {
//					int sz;
//					if (s[i] != L'"')
//						return jsElementType::Undefined;
//					std::wstring Name = parseString(s + i, sz);
//					i += sz;
//					if (s[i] != L':') 
//						return jsElementType::Undefined;
//					i++;
//					SKIP_SPACE(s, i);
//					it[Name] = parse(s + i, sz);
//					if (it[Name].Type == jsElementType::Undefined)
//						return jsElementType::Undefined;
//					i += sz;
//					SKIP_SPACE(s, i);
//					if (s[i] == L',') {
//						i++;
//						SKIP_SPACE(s, i);
//					}
//				}
//				i++;
//				SKIP_SPACE(s, i);
//				return it;
//			}
//			case L'[':
//			{
//				i++;
//				Item it = jsElementType::Array;
//				SKIP_SPACE(s, i);
//				while (s[i] != L']') {
//					int sz;
//					it.push(parse(s + i, sz));
//					if (it.Array.back().Type == jsElementType::Undefined)
//						return jsElementType::Undefined;
//					i += sz;
//					SKIP_SPACE(s, i);
//					if (s[i] == ',') {
//						i++;
//						SKIP_SPACE(s, i);
//					}
//				}
//				i++;
//				SKIP_SPACE(s, i);
//				return it;
//			}
//			default:
//				if ((s[i] >= L'0' && s[i] <= L'9') || s[i] == L'-' || s[i] == L'+') {
//					long long Int;
//					double Doub;
//					if (parseNumber(s, i, Int, Doub))
//						return Doub;
//					else
//						return Int;
//				} else if (s[i] == L'n'&&s[i + 1] == L'u'&&s[i + 2] == L'l'&&s[i + 3] == L'l') {
//					i += 4;
//					return jsElementType::Null;
//				} else if (s[i] == L't'&&s[i + 1] == L'r'&&s[i + 2] == L'u'&&s[i + 3] == L'e') {
//					i += 4;
//					return PVX::JSON::jsBoolean::True;
//				} else if (s[i] == L'f'&&s[i + 1] == L'a'&&s[i + 2] == L'l'&&s[i + 3] == L's' &&s[i + 3] == L'e') {
//					i += 5;
//					return PVX::JSON::jsBoolean::False;
//				}
//				else
//					return jsElementType::Undefined;
//			}
//		}
//
//		Item parse(const wchar_t * s) {
//			int i = 0;
//			return parse(s, i);
//		}

		Item parse(const unsigned char * data, int size) {
			if(!size)return jsElementType::Undefined;
			return parse(Decode::UTF(data, size).c_str());
		}
		Item parse(const std::vector<unsigned char>& d) {
			return parse(d.data(), d.size());
		}


		struct jsonStack {
			PVX::JSON::Item val;
			char op;
			char Empty = 0;
			std::vector<jsonStack> Child;
		};
		static std::wregex jsonSpaces(LR"regex(\s+)regex", std::regex_constants::optimize);
		static std::wregex jsonObjectStrings(LR"regex(\"((\\\"|[^\"])*)\")regex", std::regex_constants::optimize);
		static std::wregex jsonFloats(LR"regex(-?[0-9]*\.[0-9]+)regex", std::regex_constants::optimize);
		static std::wregex jsonInts(LR"regex(-?[0-9]+)regex", std::regex_constants::optimize);
		static std::wregex jsonBools(LR"regex(true|false)regex", std::regex_constants::optimize);
		static std::wregex jsonNulls(LR"regex(null)regex", std::regex_constants::optimize);

		

		void MakeObject(Item & obj, const jsonStack & s) {
			if (s.op == ':') {
				obj[s.Child[1].val.String] = s.Child[0].val;
			} else if(s.op == ','){
				for (auto & c : s.Child) MakeObject(obj, c);
			} else obj = jsElementType::Undefined;
		}
		void MakeArray(Item & obj, const jsonStack & s) {
			if (s.op == ',') 
				for (long long i = long long(s.Child.size()) - 1; i >= 0;i--) 
					MakeArray(obj, s.Child[i]);
			else obj.push(s.val);
		}

		std::pair<std::wstring, std::vector<std::wstring>> RemoveStrings(const std::wstring & txt) {
			std::wstring ret;
			std::vector<std::wstring> Strings;
			int Escape = 0;
			int Start = -1;
			int Out = 1;
			for (auto i = 0; i < txt.size(); i++) {
				auto c = txt[i];
				if (c == '\"' && !Escape) {
					if (Out) {
						//ret.pop_back();
						Start = i +1;
						Out = 0;
					}
					else {
						Strings.push_back(PVX::Decode::Unescape(txt.substr(Start, i - Start)));
						Out = 1;
					}
				}
				
				if (Out) ret.push_back(c);
				Escape = c == '\\';
			}
			return std::make_pair(ret, Strings);
		}

		Item parse(const std::wstring & Json) {
			auto prec = [](int c) {
				switch (c) {
					case '[': case '{': return 0;
					case ',': return 10;
					case ':': return 20;
				}
				return -1;
			};
			auto[tmp, Strings] = RemoveStrings(Json);
			//std::vector<std::wstring> Strings = PVX::regex_matches<std::wstring>(Json, jsonObjectStrings, [](const std::wsmatch & m) { return PVX::Decode::Unescape(m[1].str()); });
			//auto tmp = std::regex_replace(Json, jsonObjectStrings, L"\"");
			std::vector<double> Doubles = PVX::regex_matches<double>(tmp, jsonFloats, [](const std::wsmatch & m) { return _wtof(m.str().c_str()); });
			tmp = std::regex_replace(tmp, jsonFloats, L"f");
			std::vector<int> Integers = PVX::regex_matches<int>(tmp, jsonInts, [](const std::wsmatch & m) { return _wtoi(m.str().c_str()); });
			tmp = std::regex_replace(tmp, jsonInts, L"i");
			std::vector<bool> Booleans = PVX::regex_matches<bool>(tmp, jsonBools, [](const std::wsmatch & m) { return m.str()==L"true"?1:0; });
			tmp = std::regex_replace(tmp, jsonBools, L"b");
			tmp = std::regex_replace(tmp, jsonNulls, L"0");
			tmp = std::regex_replace(tmp, jsonSpaces, L"");

			std::vector<jsonStack> Output, Stack2;
			std::vector<char> Stack;
			int ItemCount = 0;
			int ints = 0, floats = 0, bools = 0, strings = 0;

			for (auto c : tmp) {
				char Empty = 0;
				switch (c) {
				case '"': Output.push_back({ Strings[strings++], 0 }); ItemCount++; break;
				case 'i': Output.push_back({ Integers[ints++], 0 }); ItemCount++; break;
				case 'f': Output.push_back({ Doubles[floats++], 0 }); ItemCount++; break;
				case 'b': Output.push_back({ Booleans[bools++] ? jsBoolean::True : jsBoolean::False, 0 }); Output.back().val.Type = jsElementType::Boolean; ItemCount++; break;
				case '0': Output.push_back({ jsElementType::Null, 0 }); ItemCount++;  break;
				case '{': Stack.push_back('{'); ItemCount = 0; break;
				case '[': Stack.push_back('['); ItemCount = 0; break;
				case ']': {
					if (Stack.size() && Stack.back() == '[' && !ItemCount) Empty = 1;
					while (Stack.size() && Stack.back() != '[') {
						Output.push_back({ jsElementType::Undefined, Stack.back() });
						Stack.pop_back();
					}
					if (!Stack.size()||Stack.back()!='[') 
						return jsElementType::Undefined;
					Stack.pop_back();
					Output.push_back({ jsElementType::Array, '[', Empty });
					ItemCount++;
					break;
				}
				case '}': {
					if (Stack.size() && Stack.back() == '{' && !ItemCount) Empty = 1;
					while (Stack.size() && Stack.back() != '{') {
						Output.push_back({ jsElementType::Undefined, Stack.back() });
						Stack.pop_back();
					}
					if (!Stack.size() || Stack.back() != '{') 
						return jsElementType::Undefined;
					Stack.pop_back();
					Output.push_back({ jsElementType::Object, '{', Empty });
					ItemCount++;
					break;
				}
				default: {
					int p = prec(c);
					while (Stack.size() && prec(Stack.back()) > p) {
						Output.push_back({ jsElementType::Undefined, Stack.back() });
						Stack.pop_back();
					}
					Stack.push_back(c);
					break;
				}

				}
			}
			while (Stack.size()) {
				Output.push_back({ jsElementType::Undefined, Stack.back() });
				Stack.pop_back();
			}

			for (auto & s : Output) {
				if (s.op) {
					if (s.op == ':' || s.op == ',') {
						if (Stack2.size() >= 2) {
							s.Child.push_back(Stack2.back());
							Stack2.pop_back();
							s.Child.push_back(Stack2.back());
							Stack2.back() = s;
							continue;
						}
						return jsElementType::Undefined;
					} else {
						if (Stack2.size()) {
							if (s.op == '{') {
								//s.val = jsElementType::Object;
								if (!s.Empty) {
									MakeObject(s.val, Stack2.back());
									Stack2.back() = s;
								} else
									Stack2.push_back(s);
								continue;
							} else {
								//s.val = jsElementType::Array;
								if (!s.Empty) {
									MakeArray(s.val, Stack2.back());
									Stack2.back() = s;
								} else
									Stack2.push_back(s);
								continue;
							}
						}
						return jsElementType::Undefined;
					}
				} else {
					Stack2.push_back(s);
				}
			}
			if (Stack2.size() == 1) return Stack2[0].val;
			return jsElementType::Undefined;
		}
	}
}