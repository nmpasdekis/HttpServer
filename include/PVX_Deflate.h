#include <vector>

#define Z_NO_COMPRESSION         0
#define Z_BEST_SPEED             1
#define Z_BEST_COMPRESSION       9
#define Z_DEFAULT_COMPRESSION  (-1)

namespace PVX {
	namespace Compress {

		int Deflate(std::vector<unsigned char> & dest, const unsigned char *source, int sSize, int level = Z_BEST_COMPRESSION);
		std::vector<unsigned char> Deflate(const std::vector<unsigned char> & data, int Level = Z_BEST_COMPRESSION);

		int Inflate(std::vector<unsigned char> & dest, const unsigned char *source, int sSize);
		std::vector<unsigned char> Inflate(const std::vector<unsigned char> & data);
	}
}