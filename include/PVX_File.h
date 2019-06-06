#ifndef __PVX_FILE_H__
#define __PVX_FILE_H__

#include<Windows.h>
#include<vector>
#include<string>
#include<PVX_json.h>
#include<thread>
#include<functional>
#include<mutex>

namespace PVX {
	namespace IO {
		class TextFile {
		public:
			TextFile();
			~TextFile();
			TextFile(const char * Filename);
			size_t Open(const char * Filename);
			std::string ReadAll();
			std::string Line(int LineNumber);
			std::vector<std::string> Lines();
			std::vector<std::string> Lines(int Start, int Count);
			int LineCount();
			void Close();
			int IsOpen();
		private:
			std::string FullPath;
			struct LineDef {
				size_t offset;
				size_t size;
			};
			FILE * fin;
			unsigned int Flags;
			std::vector<LineDef> _Lines;
			void GetLineDefs();
			void ResolvePath(const char * fn);
		};

		class ChangeTracker {
			HANDLE hFile;
			unsigned long long LastTime;
			std::wstring Filename;
			void GetLastTime();
		public:
			ChangeTracker(const std::wstring & Filename);
			operator bool();
			operator std::wstring();
		};
		class ChangeEventer{
			struct Events {
				ChangeTracker File;
				std::function<void()> Do;
			};
			std::mutex Locker;
			std::thread Tracker;
			std::vector<Events> Files;
			int Running;
		public:
			ChangeEventer();
			~ChangeEventer();
			void Track(const std::wstring & Filename, std::function<void()> clb);
		};

		class Text {
			unsigned char buffer[512];
			int BufferPosition, BufferSize;
			FILE * fin;
			std::wstring curLine;
		public:
			Text(const char * Filename);
			Text(const wchar_t * Filename);
			size_t ReadLine();
			std::wstring Line();
		};

		class BinReader {
			struct PrivateData {
				int RefCount;
				FILE * fin;
				size_t _Size;
			};
			PrivateData * pData;
		public:
			BinReader(const std::string & Filename);
			BinReader(const std::wstring & Filename);
			BinReader(const BinReader & b);
			BinReader & operator=(const BinReader& b);
			~BinReader();
			size_t Read(void * Data, int ByteCount);
			size_t Read(void * Data, int ElementSize, int ElementCount);
			void Skip(size_t nBytes);
			int Eof() const;
			int OK() const;
			size_t Size() const;
			size_t RemainingBytes() const;

			size_t CurrentPosition() const;
			void CurrentPosition(size_t pos);

			std::vector<unsigned char> Read(size_t Offset, size_t Count);
			std::string ReadString(size_t Offset, size_t Count);

			template<typename T>
			T Read() {
				T ret;
				Read(&ret, sizeof(T));
				return ret;
			}

			template<typename T>
			int ReadArray(std::vector<T> & Out, int ElementCount) {
				Out.resize(ElementCount);
				return Read(&Out[0], sizeof(T), ElementCount) == ElementCount;
			}

			template<typename T>
			int Read(T & Out) {
				return Read(&Out, sizeof(T));;
			}

			template<typename T>
			std::vector<T> ReadArray(int ItemCount) {
				std::vector<T> ret(ItemCount);
				Read(&ret[0], ItemCount * sizeof(T));
				return ret;
			}
		};

		size_t FileSize(FILE * fin);
		size_t FileSize(const std::string & filename);
		size_t FileSize(const std::wstring & filename);

		int Write(const std::string & fn, const void*data, size_t Size);
		int Write(const std::string & fn, const std::vector<unsigned char> & Data);

		int Write(const std::wstring & fn, const void*data, size_t Size);
		int Write(const std::wstring & fn, const std::vector<unsigned char> & Data);

		std::vector<unsigned char> ReadBinary(const char * Filename);
		std::vector<unsigned char> ReadBinary(const char * Filename, size_t offset, size_t length);
		size_t ReadBinary(const char * Filename, std::vector<unsigned char> & Data);
		size_t ReadBinary(const char * Filename, size_t offset, size_t length, std::vector<unsigned char> & Data);
		std::vector<unsigned char> ReadBinary(const wchar_t * Filename);
		std::vector<unsigned char> ReadBinary(const wchar_t * Filename, size_t offset, size_t length);
		size_t ReadBinary(const wchar_t * Filename, std::vector<unsigned char> & Data);
		size_t ReadBinary(const wchar_t * Filename, size_t offset, size_t length, std::vector<unsigned char> & Data);
		std::string ReadText(const char * Filename);
		std::vector<std::string> Dir(const std::string & Expression);
		std::vector<std::wstring> Dir(const std::wstring & Expression);
		std::vector<std::string> DirFull(const std::string & Expression);
		std::vector<std::wstring> DirFull(const std::wstring & Expression);
		std::vector<std::string> SubDir(const std::string & Expression);
		std::vector<std::wstring> SubDir(const std::wstring & Expression);
		std::vector<std::string> SubDirFull(const std::string & Expression);
		std::vector<std::wstring> SubDirFull(const std::wstring & Expression);
		int FileExists(const std::string & File);
		int FileExists(const std::wstring & File);
		void MakeDirectory(const std::string & Directory);
		void MakeDirectory(const std::wstring & Directory);

		std::string OpenFileDialog(HWND Parent, const char * Filter, const char * Filename = 0);
		std::wstring wOpenFileDialog(HWND Parent, const wchar_t * Filter, const wchar_t * Filename = 0);
		std::string SaveFileDialog(HWND Parent, const char * Filter, const char * Filename = 0);
		JSON::Item LoadJson(const char * Filename);
		JSON::Item LoadJson(const wchar_t * Filename);
		std::wstring wCurrentPath();
		std::string CurrentPath();
		void CurrentPath(const std::string path);
		void CurrentPath(const std::wstring path);
		std::vector<std::string> FileExtensions(const std::string &);
		std::vector<std::wstring> FileExtensions(const std::wstring &);

		std::string FileExtension(const std::string &);
		std::wstring FileExtension(const std::wstring &);

		//std::string FilePath(const std::string &);
		//std::wstring FilePath(const std::wstring &);

		std::vector<std::string> SplitPath(const std::string & Path);
		std::vector<std::wstring> SplitPath(const std::wstring & Path);

		std::string ReplaceExtension(const std::string & Filename, const std::string & NewExtension);
		std::wstring ReplaceExtension(const std::wstring & Filename, const std::wstring & NewExtension);
	};
}

#endif