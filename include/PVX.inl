#ifndef __PVX_INL__
#define __PVX_INL__

#include<vector>
#include<map>
#include<functional>
#include<random>
#include <initializer_list>
#include <set>

namespace PVX {
	template<typename T>
	inline std::vector<T> ToVector(const T * Array, size_t Count) {
		std::vector<T> ret(Count);
		memcpy(&ret[0], Array, sizeof(T) * Count);
		return ret;
	}

	template<typename T, typename T2>
	inline std::vector<T> Filter(const std::initializer_list<T> & Array, T2 condition) {
		std::vector<T> ret;
		ret.reserve(Array.size());
		for (auto & a : Array)
			if (condition(a))
				ret.push_back(a);
		ret.shrink_to_fit();
		return ret;
	}
	template<typename T, typename T2>
	inline std::vector<T> Filter(const std::vector<T> & Array, T2 condition) {
		std::vector<T> ret;
		ret.reserve(Array.size());
		for (auto & a : Array)
			if (condition(a))
				ret.push_back(a);
		ret.shrink_to_fit();
		return ret;
	}
	template<typename T, typename T2>
	inline std::pair<std::vector<T>, std::vector<T>> Separate(const std::vector<T> & Array, T2 condition) {
		std::vector<T> ret1;
		std::vector<T> ret2;
		ret1.reserve(Array.size());
		ret2.reserve(Array.size());
		for (auto & a : Array) {
			if (condition(a))
				ret1.push_back(a);
			else
				ret2.push_back(a);
		}
		ret1.shrink_to_fit();
		ret2.shrink_to_fit();
		return std::make_pair(ret1, ret2);
	}
	template<typename T>
	inline T Reduce(const std::vector<T> & Array, std::function<T(T& Result, T& item)> fnc, T Default) {
		for (auto & i : Array)
			Default = fnc(Default, i);
		return Default;
	}
	template<typename T>
	inline long long IndexOf(const std::vector<T> & Array, std::function<bool(T& a)> fnc) {
		for (long long i = 1; i < Array.size(); i++) {
			if (fnc(Array[i]))
				return i;
		}
		return -1;
	}
	std::vector<int> IndexArray(int From, int To, int Step = 1);

	inline std::vector<int> IndexArray(int From, int To, int Step) {
		std::vector<int> ret;
		ret.reserve(size_t(To) - From);
		for (auto i = From; i < To; i += Step) {
			ret.push_back(i);
		}
		return ret;
	}
	inline std::vector<int> IndexArray(int Count) {
		std::vector<int> ret(Count);
		for (auto i = 0; i < Count; i++) {
			ret[i] = i;
		}
		return ret;
	}
	inline std::vector<int> IndexArrayRef(int Count, int & Base) {
		std::vector<int> ret(Count);
		for (auto i = 0; i < Count; i++)
			ret[i] = Base++;
		return ret;
	}

	template<typename T>
	inline void Randomize(std::vector<T> & v) {
		for (int i = 0; i < v.size(); i++) {
			int r = ((std::rand() << 24) ^ (std::rand() << 16) ^ (std::rand() << 8) ^ (std::rand())) % v.size();
			if (i != r) {
				T tmp = v[i];
				v[i] = v[r];
				v[r] = tmp;
			}
		}
	}

	template<typename T1, typename T2>
	inline auto Map(const T1 & Array, size_t Count, T2 cvt, size_t Start = 0, size_t Size = 0);
	template<typename T1, typename T2>
	inline auto Map(const T1 & Array, size_t Count, T2 cvt, size_t Start, size_t Size) {
		if (!Size)Size = Count;
		std::vector<decltype(cvt(Array[0]))> ret(Count);
		for (auto i = Start; i < Size; i++)
			ret[i] = cvt(Array[i]);
		return ret;
	}

	//template<typename T1, typename T2>
	//inline auto Map(const T1 * Array, size_t Count, T2 cvt, size_t Start = 0, size_t Size = 0);
	//template<typename T1, typename T2>
	//inline auto Map(const T1 * Array, size_t Count, T2 cvt, size_t Start, size_t Size) {
	//	if(!Size)Size = Count;
	//	std::vector<decltype(cvt(Array[0]))> ret(Count);
	//	for(auto i = Start; i < Size; i++)
	//		ret[i] = cvt(Array[i]);
	//	return ret;
	//}

	template<typename T1, typename T2>
	inline auto Map(const T1 & Array, T2 cvt, size_t Start, size_t Size = 0);
	template<typename T1, typename T2>
	inline auto Map(const T1 & Array, T2 cvt, size_t Start, size_t Size) {
		if (!Size)Size = Array.size();
		std::vector<decltype(cvt(Array[0]))> ret;
		ret.reserve(Array.size());
		for (auto i = Start; i < Size; i++)
			ret.push_back(cvt(Array[i]));
		return ret;
	}

	template<typename T>
	inline auto Map(size_t Count, T fnc, const size_t Base = 0);
	template<typename T>
	inline auto Map(size_t Count, T fnc, const size_t Base) {
		std::vector<decltype(fnc(0))> ret(Count - Base);
		for (auto i = Base; i < Count; i++) {
			ret[i - Base] = fnc(i);
		}
		return ret;
	}

	template<typename T1, typename T2>
	void forEach(const std::vector<T1> & Array, T2 fnc) {
		std::for_each(Array.begin(), Array.end(), fnc);
	}
	template<typename KeyType, typename ValueType>
	void forEach(const std::map<KeyType, ValueType> & Map, std::function<void(const KeyType&, const ValueType&)> fnc) {
		std::for_each(Map.begin(), Map.end(), [fnc](const std::pair<KeyType, ValueType>&p) {
			fnc(p.first, p.second);
		});
	}

	template<typename T1, typename T2>
	inline auto Map(const std::vector<T1> & Array, T2 fnc) {
		std::vector<decltype(fnc(Array[0]))> ret(Array.size());
		std::transform(Array.begin(), Array.end(), ret.begin(), fnc);
		return ret;
	}

	template<typename T1, typename T2>
	inline std::vector<T1> Keys(const std::map<T1, T2> & dict) {
		std::vector<T1> ret;
		for (auto & kv : dict) {
			ret.push_back(kv.first);
		}
		return ret;
	}
	template<typename T>
	inline std::set<T> ToSet(const std::vector<T>& arr) {
		std::set<T> ret;
		for (auto & i : arr)ret.insert(i);
		return ret;
	}

	template<typename T1, typename T2>
	inline auto ToSet(const T1 & Array, T2 fnc) {
		std::set<decltype(fnc(Array[0]))> ret;
		for (auto & i : Array)ret.insert(fnc(i));
		return ret;
	}

	template<typename Container, typename result, typename Operation>
	inline result Reduce(const Container& Array, const result& Default, Operation Op) {
		return std::reduce(Array.begin(), Array.end(), Default, Op);
	}

	class RefCounter {
		int * ref;
	public:
		inline RefCounter() : ref{ new int[1] } { *ref = 1; }
		inline RefCounter(const RefCounter && r) : ref{ r.ref } { (*ref)++; }
		inline RefCounter(const RefCounter & r) : ref{ r.ref } { (*ref)++; }
		inline ~RefCounter() { 
			if (!--(*ref)) delete ref; 
		}
		inline RefCounter & operator=(const RefCounter & r) {
			if (!--(*ref)) delete ref;
			ref = r.ref;
			(*ref)++;
			return *this;
		}
		inline operator int() { return *ref; }
		inline bool operator!() { return !((*ref)-1); }
		inline int operator++() { return (*ref)++; }
	};

	inline long long IndexOfBinary(const unsigned char * Data, long long DataSize, const unsigned char * Find, long long FindSize, long long Start=0) {
		DataSize -= FindSize;
		for (long long i = Start; i < DataSize; i++) {
			if (!memcmp(Data + i, Find, FindSize)) return i;
		}
		return -1;
	}
	inline void Interleave(void * Dest, int DestStride, const void * Src, int SrcStride, int Count) {
		unsigned char * dst = (unsigned char*)Dest;
		unsigned char * src = (unsigned char*)Src;
		int dif = (DestStride - SrcStride);
		int sz = SrcStride + (dif & (dif >> ((sizeof(int) << 3) - 1)));
		for (int i = 0; i < Count; i++) {
			memcpy(dst, src, sz);
			dst += DestStride;
			src += SrcStride;
		}
	}
}

#endif