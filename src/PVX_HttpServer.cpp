#include<PVX_Network.h>
#include<PVX_File.h>
#include<PVX_Encode.h>
#include<regex>
#include<map>
#include <PVX_Deflate.h>
#include<PVX_StdString.h>
#include<chrono>

using namespace std::chrono_literals;



namespace PVX {
	namespace Network {
		typedef unsigned char uchar;

		HttpServer::HttpServer() :DefaultRoute{ L"/{Path}", ContentServer() }, Mime{
			{ L"3dm", L"x-world/x-3dmf" },
			{ L"3dmf", L"x-world/x-3dmf" },
			{ L"a", L"application/octet-stream" },
			{ L"aab", L"application/x-authorware-bin" },
			{ L"aam", L"application/x-authorware-map" },
			{ L"aas", L"application/x-authorware-seg" },
			{ L"abc", L"text/vnd.abc" },
			{ L"acgi", L"text/html" },
			{ L"afl", L"video/animaflex" },
			{ L"ai", L"application/postscript" },
			{ L"aif", L"audio/aiff" },
			{ L"aif", L"audio/x-aiff" },
			{ L"aifc", L"audio/aiff" },
			{ L"aifc", L"audio/x-aiff" },
			{ L"aiff", L"audio/aiff" },
			{ L"aiff", L"audio/x-aiff" },
			{ L"aim", L"application/x-aim" },
			{ L"aip", L"text/x-audiosoft-intra" },
			{ L"ani", L"application/x-navi-animation" },
			{ L"aos", L"application/x-nokia-9000-communicator-add-on-software" },
			{ L"aps", L"application/mime" },
			{ L"arc", L"application/octet-stream" },
			{ L"arj", L"application/arj" },
			{ L"arj", L"application/octet-stream" },
			{ L"art", L"image/x-jg" },
			{ L"asf", L"video/x-ms-asf" },
			{ L"asm", L"text/x-asm" },
			{ L"asp", L"text/asp" },
			{ L"asx", L"application/x-mplayer2" },
			{ L"asx", L"video/x-ms-asf" },
			{ L"asx", L"video/x-ms-asf-plugin" },
			{ L"au", L"audio/basic" },
			{ L"au", L"audio/x-au" },
			//{ L"avi", L"video/avi" },
			//{ L"avi", L"application/x-troff-msvideo" },
			//{ L"avi", L"video/msvideo" },
			{ L"avi", L"video/x-msvideo" },
			//{ L"avs", L"video/avs-video" },
			{ L"bcpio", L"application/x-bcpio" },
			//{ L"bin", L"application/mac-binary" },
			//{ L"bin", L"application/macbinary" },
			//{ L"bin", L"application/x-binary" },
			//{ L"bin", L"application/x-macbinary" },
			{ L"bin", L"application/octet-stream" },
			{ L"bm", L"image/bmp" },
			{ L"bmp", L"image/bmp" },
			{ L"bmp", L"image/x-windows-bmp" },
			{ L"boo", L"application/book" },
			{ L"book", L"application/book" },
			{ L"boz", L"application/x-bzip2" },
			{ L"bsh", L"application/x-bsh" },
			{ L"bz", L"application/x-bzip" },
			{ L"bz2", L"application/x-bzip2" },
			{ L"c", L"text/plain" },
			{ L"c", L"text/x-c" },
			{ L"c++", L"text/plain" },
			{ L"cat", L"application/vnd.ms-pki.seccat" },
			{ L"cc", L"text/plain" },
			{ L"cc", L"text/x-c" },
			{ L"ccad", L"application/clariscad" },
			{ L"cco", L"application/x-cocoa" },
			{ L"cdf", L"application/cdf" },
			{ L"cdf", L"application/x-cdf" },
			{ L"cdf", L"application/x-netcdf" },
			{ L"cer", L"application/pkix-cert" },
			{ L"cer", L"application/x-x509-ca-cert" },
			{ L"cha", L"application/x-chat" },
			{ L"chat", L"application/x-chat" },
			{ L"class", L"application/java" },
			{ L"class", L"application/java-byte-code" },
			{ L"class", L"application/x-java-class" },
			{ L"com", L"application/octet-stream" },
			{ L"com", L"text/plain" },
			{ L"conf", L"text/plain" },
			{ L"cpio", L"application/x-cpio" },
			{ L"cpp", L"text/x-c" },
			{ L"cpt", L"application/mac-compactpro" },
			{ L"cpt", L"application/x-compactpro" },
			{ L"cpt", L"application/x-cpt" },
			{ L"crl", L"application/pkcs-crl" },
			{ L"crl", L"application/pkix-crl" },
			{ L"crt", L"application/pkix-cert" },
			{ L"crt", L"application/x-x509-ca-cert" },
			{ L"crt", L"application/x-x509-user-cert" },
			{ L"csh", L"application/x-csh" },
			{ L"csh", L"text/x-script.csh" },
			{ L"css", L"text/css" },
			{ L"css", L"application/x-pointplus" },
			{ L"cxx", L"text/plain" },
			{ L"dcr", L"application/x-director" },
			{ L"deepv", L"application/x-deepv" },
			{ L"def", L"text/plain" },
			{ L"der", L"application/x-x509-ca-cert" },
			{ L"dif", L"video/x-dv" },
			{ L"dir", L"application/x-director" },
			{ L"dl", L"video/dl" },
			{ L"dl", L"video/x-dl" },
			{ L"doc", L"application/msword" },
			{ L"dot", L"application/msword" },
			{ L"dp", L"application/commonground" },
			{ L"drw", L"application/drafting" },
			{ L"dump", L"application/octet-stream" },
			{ L"dv", L"video/x-dv" },
			{ L"dvi", L"application/x-dvi" },
			{ L"dwf", L"drawing/x-dwf (old)" },
			{ L"dwf", L"model/vnd.dwf" },
			{ L"dwg", L"application/acad" },
			{ L"dwg", L"image/vnd.dwg" },
			{ L"dwg", L"image/x-dwg" },
			{ L"dxf", L"application/dxf" },
			{ L"dxf", L"image/vnd.dwg" },
			{ L"dxf", L"image/x-dwg" },
			{ L"dxr", L"application/x-director" },
			{ L"el", L"text/x-script.elisp" },
			{ L"elc", L"application/x-bytecode.elisp (compiled elisp)" },
			{ L"elc", L"application/x-elc" },
			{ L"env", L"application/x-envoy" },
			{ L"eps", L"application/postscript" },
			{ L"es", L"application/x-esrehber" },
			{ L"etx", L"text/x-setext" },
			{ L"evy", L"application/envoy" },
			{ L"evy", L"application/x-envoy" },
			{ L"exe", L"application/octet-stream" },
			{ L"f", L"text/plain" },
			{ L"f", L"text/x-fortran" },
			{ L"f77", L"text/x-fortran" },
			{ L"f90", L"text/plain" },
			{ L"f90", L"text/x-fortran" },
			{ L"fdf", L"application/vnd.fdf" },
			{ L"fif", L"application/fractals" },
			{ L"fif", L"image/fif" },
			{ L"fli", L"video/fli" },
			{ L"fli", L"video/x-fli" },
			{ L"flo", L"image/florian" },
			{ L"flx", L"text/vnd.fmi.flexstor" },
			{ L"fmf", L"video/x-atomic3d-feature" },
			{ L"for", L"text/plain" },
			{ L"for", L"text/x-fortran" },
			{ L"fpx", L"image/vnd.fpx" },
			{ L"fpx", L"image/vnd.net-fpx" },
			{ L"frl", L"application/freeloader" },
			{ L"funk", L"audio/make" },
			{ L"g", L"text/plain" },
			{ L"g3", L"image/g3fax" },
			{ L"gif", L"image/gif" },
			{ L"gl", L"video/gl" },
			{ L"gl", L"video/x-gl" },
			{ L"gsd", L"audio/x-gsm" },
			{ L"gsm", L"audio/x-gsm" },
			{ L"gsp", L"application/x-gsp" },
			{ L"gss", L"application/x-gss" },
			{ L"gtar", L"application/x-gtar" },
			{ L"gz", L"application/x-compressed" },
			{ L"gz", L"application/x-gzip" },
			{ L"gzip", L"application/x-gzip" },
			{ L"gzip", L"multipart/x-gzip" },
			{ L"h", L"text/plain" },
			{ L"h", L"text/x-h" },
			{ L"hdf", L"application/x-hdf" },
			{ L"help", L"application/x-helpfile" },
			{ L"hgl", L"application/vnd.hp-hpgl" },
			{ L"hh", L"text/plain" },
			{ L"hh", L"text/x-h" },
			{ L"hlb", L"text/x-script" },
			{ L"hlp", L"application/hlp" },
			{ L"hlp", L"application/x-helpfile" },
			{ L"hlp", L"application/x-winhelp" },
			{ L"hpg", L"application/vnd.hp-hpgl" },
			{ L"hpgl", L"application/vnd.hp-hpgl" },
			{ L"hqx", L"application/binhex" },
			{ L"hqx", L"application/binhex4" },
			{ L"hqx", L"application/mac-binhex" },
			{ L"hqx", L"application/mac-binhex40" },
			{ L"hqx", L"application/x-binhex40" },
			{ L"hqx", L"application/x-mac-binhex40" },
			{ L"hta", L"application/hta" },
			{ L"htc", L"text/x-component" },
			{ L"htm", L"text/html" },
			{ L"html", L"text/html" },
			{ L"htmls", L"text/html" },
			{ L"htt", L"text/webviewhtml" },
			{ L"htx", L"text/html" },
			{ L"ice", L"x-conference/x-cooltalk" },
			{ L"ico", L"image/x-icon" },
			{ L"idc", L"text/plain" },
			{ L"ief", L"image/ief" },
			{ L"iefs", L"image/ief" },
			{ L"iges", L"application/iges" },
			{ L"iges", L"model/iges" },
			{ L"igs", L"application/iges" },
			{ L"igs", L"model/iges" },
			{ L"ima", L"application/x-ima" },
			{ L"imap", L"application/x-httpd-imap" },
			{ L"inf", L"application/inf" },
			{ L"ins", L"application/x-internett-signup" },
			{ L"ip", L"application/x-ip2" },
			{ L"isu", L"video/x-isvideo" },
			{ L"it", L"audio/it" },
			{ L"iv", L"application/x-inventor" },
			{ L"ivr", L"i-world/i-vrml" },
			{ L"ivy", L"application/x-livescreen" },
			{ L"jam", L"audio/x-jam" },
			{ L"jav", L"text/plain" },
			{ L"jav", L"text/x-java-source" },
			{ L"java", L"text/plain" },
			{ L"java", L"text/x-java-source" },
			{ L"jcm", L"application/x-java-commerce" },
			{ L"jfif", L"image/jpeg" },
			{ L"jfif", L"image/pjpeg" },
			{ L"jfif-tbnl", L"image/jpeg" },
			{ L"jpe", L"image/jpeg" },
			{ L"jpe", L"image/pjpeg" },
			{ L"jpeg", L"image/jpeg" },
			{ L"jpeg", L"image/pjpeg" },
			{ L"jpg", L"image/jpeg" },
			{ L"jpg", L"image/pjpeg" },
			{ L"jps", L"image/x-jps" },
			{ L"js", L"application/x-javascript" },
			{ L"js", L"application/javascript" },
			{ L"js", L"application/ecmascript" },
			{ L"js", L"text/javascript" },
			{ L"js", L"text/ecmascript" },
			{ L"jut", L"image/jutvision" },
			{ L"kar", L"audio/midi" },
			{ L"kar", L"music/x-karaoke" },
			{ L"ksh", L"application/x-ksh" },
			{ L"ksh", L"text/x-script.ksh" },
			{ L"la", L"audio/nspaudio" },
			{ L"la", L"audio/x-nspaudio" },
			{ L"lam", L"audio/x-liveaudio" },
			{ L"latex", L"application/x-latex" },
			{ L"lha", L"application/lha" },
			{ L"lha", L"application/octet-stream" },
			{ L"lha", L"application/x-lha" },
			{ L"lhx", L"application/octet-stream" },
			{ L"list", L"text/plain" },
			{ L"lma", L"audio/nspaudio" },
			{ L"lma", L"audio/x-nspaudio" },
			{ L"log", L"text/plain" },
			{ L"lsp", L"application/x-lisp" },
			{ L"lsp", L"text/x-script.lisp" },
			{ L"lst", L"text/plain" },
			{ L"lsx", L"text/x-la-asf" },
			{ L"ltx", L"application/x-latex" },
			{ L"lzh", L"application/octet-stream" },
			{ L"lzh", L"application/x-lzh" },
			{ L"lzx", L"application/lzx" },
			{ L"lzx", L"application/octet-stream" },
			{ L"lzx", L"application/x-lzx" },
			{ L"m", L"text/plain" },
			{ L"m", L"text/x-m" },
			{ L"m1v", L"video/mpeg" },
			{ L"m2a", L"audio/mpeg" },
			{ L"m2v", L"video/mpeg" },
			{ L"m3u", L"audio/x-mpequrl" },
			{ L"man", L"application/x-troff-man" },
			{ L"map", L"application/x-navimap" },
			{ L"mar", L"text/plain" },
			{ L"mbd", L"application/mbedlet" },
			{ L"mc$", L"application/x-magic-cap-package-1.0" },
			{ L"mcd", L"application/mcad" },
			{ L"mcd", L"application/x-mathcad" },
			{ L"mcf", L"image/vasa" },
			{ L"mcf", L"text/mcf" },
			{ L"mcp", L"application/netmc" },
			{ L"me", L"application/x-troff-me" },
			{ L"mht", L"message/rfc822" },
			{ L"mhtml", L"message/rfc822" },
			{ L"mid", L"application/x-midi" },
			{ L"mid", L"audio/midi" },
			{ L"mid", L"audio/x-mid" },
			{ L"mid", L"audio/x-midi" },
			{ L"mid", L"music/crescendo" },
			{ L"mid", L"x-music/x-midi" },
			{ L"midi", L"application/x-midi" },
			{ L"midi", L"audio/midi" },
			{ L"midi", L"audio/x-mid" },
			{ L"midi", L"audio/x-midi" },
			{ L"midi", L"music/crescendo" },
			{ L"midi", L"x-music/x-midi" },
			{ L"mif", L"application/x-frame" },
			{ L"mif", L"application/x-mif" },
			{ L"mime", L"message/rfc822" },
			{ L"mime", L"www/mime" },
			{ L"mjf", L"audio/x-vnd.audioexplosion.mjuicemediafile" },
			{ L"mjpg", L"video/x-motion-jpeg" },
			{ L"mkv", L"video/webm" },
			{ L"mm", L"application/base64" },
			{ L"mm", L"application/x-meme" },
			{ L"mme", L"application/base64" },
			{ L"mod", L"audio/mod" },
			{ L"mod", L"audio/x-mod" },
			{ L"moov", L"video/quicktime" },
			{ L"mov", L"video/quicktime" },
			{ L"movie", L"video/x-sgi-movie" },
			{ L"mp2", L"audio/mpeg" },
			{ L"mp2", L"audio/x-mpeg" },
			{ L"mp2", L"video/mpeg" },
			{ L"mp2", L"video/x-mpeg" },
			{ L"mp2", L"video/x-mpeq2a" },
			{ L"mp3", L"audio/mpeg3" },
			{ L"mp3", L"audio/x-mpeg-3" },
			{ L"mp3", L"video/mpeg" },
			{ L"mp3", L"video/x-mpeg" },
			{ L"mp4", L"video/mp4" },
			{ L"mpa", L"audio/mpeg" },
			{ L"mpa", L"video/mpeg" },
			{ L"mpc", L"application/x-project" },
			{ L"mpe", L"video/mpeg" },
			{ L"mpeg", L"video/mpeg" },
			{ L"mpg", L"audio/mpeg" },
			{ L"mpg", L"video/mpeg" },
			{ L"mpga", L"audio/mpeg" },
			{ L"mpp", L"application/vnd.ms-project" },
			{ L"mpt", L"application/x-project" },
			{ L"mpv", L"application/x-project" },
			{ L"mpx", L"application/x-project" },
			{ L"mrc", L"application/marc" },
			{ L"ms", L"application/x-troff-ms" },
			{ L"mv", L"video/x-sgi-movie" },
			{ L"my", L"audio/make" },
			{ L"mzz", L"application/x-vnd.audioexplosion.mzz" },
			{ L"nap", L"image/naplps" },
			{ L"naplps", L"image/naplps" },
			{ L"nc", L"application/x-netcdf" },
			{ L"ncm", L"application/vnd.nokia.configuration-message" },
			{ L"nif", L"image/x-niff" },
			{ L"niff", L"image/x-niff" },
			{ L"nix", L"application/x-mix-transfer" },
			{ L"nsc", L"application/x-conference" },
			{ L"nvd", L"application/x-navidoc" },
			{ L"o", L"application/octet-stream" },
			{ L"oda", L"application/oda" },
			{ L"omc", L"application/x-omc" },
			{ L"omcd", L"application/x-omcdatamaker" },
			{ L"omcr", L"application/x-omcregerator" },
			{ L"p", L"text/x-pascal" },
			{ L"p10", L"application/pkcs10" },
			{ L"p10", L"application/x-pkcs10" },
			{ L"p12", L"application/pkcs-12" },
			{ L"p12", L"application/x-pkcs12" },
			{ L"p7a", L"application/x-pkcs7-signature" },
			{ L"p7c", L"application/pkcs7-mime" },
			{ L"p7c", L"application/x-pkcs7-mime" },
			{ L"p7m", L"application/pkcs7-mime" },
			{ L"p7m", L"application/x-pkcs7-mime" },
			{ L"p7r", L"application/x-pkcs7-certreqresp" },
			{ L"p7s", L"application/pkcs7-signature" },
			{ L"part", L"application/pro_eng" },
			{ L"pas", L"text/pascal" },
			{ L"pbm", L"image/x-portable-bitmap" },
			{ L"pcl", L"application/vnd.hp-pcl" },
			{ L"pcl", L"application/x-pcl" },
			{ L"pct", L"image/x-pict" },
			{ L"pcx", L"image/x-pcx" },
			{ L"pdb", L"chemical/x-pdb" },
			{ L"pdf", L"application/pdf" },
			{ L"pfunk", L"audio/make" },
			{ L"pfunk", L"audio/make.my.funk" },
			{ L"pgm", L"image/x-portable-graymap" },
			{ L"pgm", L"image/x-portable-greymap" },
			{ L"pic", L"image/pict" },
			{ L"pict", L"image/pict" },
			{ L"pkg", L"application/x-newton-compatible-pkg" },
			{ L"pko", L"application/vnd.ms-pki.pko" },
			{ L"pl", L"text/plain" },
			{ L"pl", L"text/x-script.perl" },
			{ L"plx", L"application/x-pixclscript" },
			{ L"pm", L"image/x-xpixmap" },
			{ L"pm", L"text/x-script.perl-module" },
			{ L"pm4", L"application/x-pagemaker" },
			{ L"pm5", L"application/x-pagemaker" },
			{ L"png", L"image/png" },
			{ L"pnm", L"application/x-portable-anymap" },
			{ L"pnm", L"image/x-portable-anymap" },
			{ L"pot", L"application/mspowerpoint" },
			{ L"pot", L"application/vnd.ms-powerpoint" },
			{ L"pov", L"model/x-pov" },
			{ L"ppa", L"application/vnd.ms-powerpoint" },
			{ L"ppm", L"image/x-portable-pixmap" },
			{ L"pps", L"application/mspowerpoint" },
			{ L"pps", L"application/vnd.ms-powerpoint" },
			{ L"ppt", L"application/mspowerpoint" },
			{ L"ppt", L"application/powerpoint" },
			{ L"ppt", L"application/vnd.ms-powerpoint" },
			{ L"ppt", L"application/x-mspowerpoint" },
			{ L"ppz", L"application/mspowerpoint" },
			{ L"pre", L"application/x-freelance" },
			{ L"prt", L"application/pro_eng" },
			{ L"ps", L"application/postscript" },
			{ L"psd", L"application/octet-stream" },
			{ L"pvu", L"paleovu/x-pv" },
			{ L"pwz", L"application/vnd.ms-powerpoint" },
			{ L"py", L"text/x-script.phyton" },
			{ L"pyc", L"application/x-bytecode.python" },
			{ L"qcp", L"audio/vnd.qcelp" },
			{ L"qd3", L"x-world/x-3dmf" },
			{ L"qd3d", L"x-world/x-3dmf" },
			{ L"qif", L"image/x-quicktime" },
			{ L"qt", L"video/quicktime" },
			{ L"qtc", L"video/x-qtc" },
			{ L"qti", L"image/x-quicktime" },
			{ L"qtif", L"image/x-quicktime" },
			{ L"ra", L"audio/x-pn-realaudio" },
			{ L"ra", L"audio/x-pn-realaudio-plugin" },
			{ L"ra", L"audio/x-realaudio" },
			{ L"ram", L"audio/x-pn-realaudio" },
			{ L"ras", L"application/x-cmu-raster" },
			{ L"ras", L"image/cmu-raster" },
			{ L"ras", L"image/x-cmu-raster" },
			{ L"rast", L"image/cmu-raster" },
			{ L"rexx", L"text/x-script.rexx" },
			{ L"rf", L"image/vnd.rn-realflash" },
			{ L"rgb", L"image/x-rgb" },
			{ L"rm", L"application/vnd.rn-realmedia" },
			{ L"rm", L"audio/x-pn-realaudio" },
			{ L"rmi", L"audio/mid" },
			{ L"rmm", L"audio/x-pn-realaudio" },
			{ L"rmp", L"audio/x-pn-realaudio" },
			{ L"rmp", L"audio/x-pn-realaudio-plugin" },
			{ L"rng", L"application/ringing-tones" },
			{ L"rng", L"application/vnd.nokia.ringing-tone" },
			{ L"rnx", L"application/vnd.rn-realplayer" },
			{ L"roff", L"application/x-troff" },
			{ L"rp", L"image/vnd.rn-realpix" },
			{ L"rpm", L"audio/x-pn-realaudio-plugin" },
			{ L"rt", L"text/richtext" },
			{ L"rt", L"text/vnd.rn-realtext" },
			{ L"rtf", L"application/rtf" },
			{ L"rtf", L"application/x-rtf" },
			{ L"rtf", L"text/richtext" },
			{ L"rtx", L"application/rtf" },
			{ L"rtx", L"text/richtext" },
			{ L"rv", L"video/vnd.rn-realvideo" },
			{ L"s", L"text/x-asm" },
			{ L"s3m", L"audio/s3m" },
			{ L"saveme", L"application/octet-stream" },
			{ L"sbk", L"application/x-tbook" },
			{ L"scm", L"application/x-lotusscreencam" },
			{ L"scm", L"text/x-script.guile" },
			{ L"scm", L"text/x-script.scheme" },
			{ L"scm", L"video/x-scm" },
			{ L"sdml", L"text/plain" },
			{ L"sdp", L"application/sdp" },
			{ L"sdp", L"application/x-sdp" },
			{ L"sdr", L"application/sounder" },
			{ L"sea", L"application/sea" },
			{ L"sea", L"application/x-sea" },
			{ L"set", L"application/set" },
			{ L"sgm", L"text/sgml" },
			{ L"sgm", L"text/x-sgml" },
			{ L"sgml", L"text/sgml" },
			{ L"sgml", L"text/x-sgml" },
			{ L"sh", L"application/x-bsh" },
			{ L"sh", L"application/x-sh" },
			{ L"sh", L"application/x-shar" },
			{ L"sh", L"text/x-script.sh" },
			{ L"shar", L"application/x-bsh" },
			{ L"shar", L"application/x-shar" },
			{ L"shtml", L"text/html" },
			{ L"shtml", L"text/x-server-parsed-html" },
			{ L"sid", L"audio/x-psid" },
			{ L"sit", L"application/x-sit" },
			{ L"sit", L"application/x-stuffit" },
			{ L"skd", L"application/x-koan" },
			{ L"skm", L"application/x-koan" },
			{ L"skp", L"application/x-koan" },
			{ L"skt", L"application/x-koan" },
			{ L"sl", L"application/x-seelogo" },
			{ L"smi", L"application/smil" },
			{ L"smil", L"application/smil" },
			{ L"snd", L"audio/basic" },
			{ L"snd", L"audio/x-adpcm" },
			{ L"sol", L"application/solids" },
			{ L"spc", L"application/x-pkcs7-certificates" },
			{ L"spc", L"text/x-speech" },
			{ L"spl", L"application/futuresplash" },
			{ L"spr", L"application/x-sprite" },
			{ L"sprite", L"application/x-sprite" },
			{ L"src", L"application/x-wais-source" },
			{ L"ssi", L"text/x-server-parsed-html" },
			{ L"ssm", L"application/streamingmedia" },
			{ L"sst", L"application/vnd.ms-pki.certstore" },
			{ L"step", L"application/step" },
			{ L"stl", L"application/sla" },
			{ L"stl", L"application/vnd.ms-pki.stl" },
			{ L"stl", L"application/x-navistyle" },
			{ L"stp", L"application/step" },
			{ L"sv4cpio", L"application/x-sv4cpio" },
			{ L"sv4crc", L"application/x-sv4crc" },
			{ L"svf", L"image/vnd.dwg" },
			{ L"svf", L"image/x-dwg" },
			{ L"svr", L"application/x-world" },
			{ L"svr", L"x-world/x-svr" },
			{ L"swf", L"application/x-shockwave-flash" },
			{ L"t", L"application/x-troff" },
			{ L"talk", L"text/x-speech" },
			{ L"tar", L"application/x-tar" },
			{ L"tbk", L"application/toolbook" },
			{ L"tbk", L"application/x-tbook" },
			{ L"tcl", L"application/x-tcl" },
			{ L"tcl", L"text/x-script.tcl" },
			{ L"tcsh", L"text/x-script.tcsh" },
			{ L"tex", L"application/x-tex" },
			{ L"texi", L"application/x-texinfo" },
			{ L"texinfo", L"application/x-texinfo" },
			{ L"text", L"application/plain" },
			{ L"text", L"text/plain" },
			{ L"tgz", L"application/gnutar" },
			{ L"tgz", L"application/x-compressed" },
			{ L"tif", L"image/tiff" },
			{ L"tif", L"image/x-tiff" },
			{ L"tiff", L"image/tiff" },
			{ L"tiff", L"image/x-tiff" },
			{ L"tr", L"application/x-troff" },
			{ L"tsi", L"audio/tsp-audio" },
			{ L"tsp", L"application/dsptype" },
			{ L"tsp", L"audio/tsplayer" },
			{ L"tsv", L"text/tab-separated-values" },
			{ L"turbot", L"image/florian" },
			{ L"txt", L"text/plain" },
			{ L"uil", L"text/x-uil" },
			{ L"uni", L"text/uri-list" },
			{ L"unis", L"text/uri-list" },
			{ L"unv", L"application/i-deas" },
			{ L"uri", L"text/uri-list" },
			{ L"uris", L"text/uri-list" },
			{ L"ustar", L"application/x-ustar" },
			{ L"ustar", L"multipart/x-ustar" },
			{ L"uu", L"application/octet-stream" },
			{ L"uu", L"text/x-uuencode" },
			{ L"uue", L"text/x-uuencode" },
			{ L"vcd", L"application/x-cdlink" },
			{ L"vcs", L"text/x-vcalendar" },
			{ L"vda", L"application/vda" },
			{ L"vdo", L"video/vdo" },
			{ L"vew", L"application/groupwise" },
			{ L"viv", L"video/vivo" },
			{ L"viv", L"video/vnd.vivo" },
			{ L"vivo", L"video/vivo" },
			{ L"vivo", L"video/vnd.vivo" },
			{ L"vmd", L"application/vocaltec-media-desc" },
			{ L"vmf", L"application/vocaltec-media-file" },
			{ L"voc", L"audio/voc" },
			{ L"voc", L"audio/x-voc" },
			{ L"vos", L"video/vosaic" },
			{ L"vox", L"audio/voxware" },
			{ L"vqe", L"audio/x-twinvq-plugin" },
			{ L"vqf", L"audio/x-twinvq" },
			{ L"vql", L"audio/x-twinvq-plugin" },
			{ L"vrml", L"application/x-vrml" },
			{ L"vrml", L"model/vrml" },
			{ L"vrml", L"x-world/x-vrml" },
			{ L"vrt", L"x-world/x-vrt" },
			{ L"vsd", L"application/x-visio" },
			{ L"vst", L"application/x-visio" },
			{ L"vsw", L"application/x-visio" },
			{ L"vtt", L"text/vtt" },
			{ L"w60", L"application/wordperfect6.0" },
			{ L"w61", L"application/wordperfect6.1" },
			{ L"w6w", L"application/msword" },
			{ L"wav", L"audio/wav" },
			{ L"wav", L"audio/x-wav" },
			{ L"wb1", L"application/x-qpro" },
			{ L"wbmp", L"image/vnd.wap.wbmp" },
			{ L"web", L"application/vnd.xara" },
			{ L"wiz", L"application/msword" },
			{ L"wk1", L"application/x-123" },
			{ L"wmf", L"windows/metafile" },
			{ L"wml", L"text/vnd.wap.wml" },
			{ L"wmlc", L"application/vnd.wap.wmlc" },
			{ L"wmls", L"text/vnd.wap.wmlscript" },
			{ L"wmlsc", L"application/vnd.wap.wmlscriptc" },
			{ L"word", L"application/msword" },
			{ L"wp", L"application/wordperfect" },
			{ L"wp5", L"application/wordperfect" },
			{ L"wp5", L"application/wordperfect6.0" },
			{ L"wp6", L"application/wordperfect" },
			{ L"wpd", L"application/wordperfect" },
			{ L"wpd", L"application/x-wpwin" },
			{ L"wq1", L"application/x-lotus" },
			{ L"wri", L"application/mswrite" },
			{ L"wri", L"application/x-wri" },
			{ L"wrl", L"application/x-world" },
			{ L"wrl", L"model/vrml" },
			{ L"wrl", L"x-world/x-vrml" },
			{ L"wrz", L"model/vrml" },
			{ L"wrz", L"x-world/x-vrml" },
			{ L"wsc", L"text/scriplet" },
			{ L"wsrc", L"application/x-wais-source" },
			{ L"wtk", L"application/x-wintalk" },
			{ L"xbm", L"image/x-xbitmap" },
			{ L"xbm", L"image/x-xbm" },
			{ L"xbm", L"image/xbm" },
			{ L"xdr", L"video/x-amt-demorun" },
			{ L"xgz", L"xgl/drawing" },
			{ L"xif", L"image/vnd.xiff" },
			{ L"xl", L"application/excel" },
			{ L"xla", L"application/excel" },
			{ L"xla", L"application/x-excel" },
			{ L"xla", L"application/x-msexcel" },
			{ L"xlb", L"application/excel" },
			{ L"xlb", L"application/vnd.ms-excel" },
			{ L"xlb", L"application/x-excel" },
			{ L"xlc", L"application/excel" },
			{ L"xlc", L"application/vnd.ms-excel" },
			{ L"xlc", L"application/x-excel" },
			{ L"xld", L"application/excel" },
			{ L"xld", L"application/x-excel" },
			{ L"xlk", L"application/excel" },
			{ L"xlk", L"application/x-excel" },
			{ L"xll", L"application/excel" },
			{ L"xll", L"application/vnd.ms-excel" },
			{ L"xll", L"application/x-excel" },
			{ L"xlm", L"application/excel" },
			{ L"xlm", L"application/vnd.ms-excel" },
			{ L"xlm", L"application/x-excel" },
			{ L"xls", L"application/excel" },
			{ L"xls", L"application/vnd.ms-excel" },
			{ L"xls", L"application/x-excel" },
			{ L"xls", L"application/x-msexcel" },
			{ L"xlt", L"application/excel" },
			{ L"xlt", L"application/x-excel" },
			{ L"xlv", L"application/excel" },
			{ L"xlv", L"application/x-excel" },
			{ L"xlw", L"application/excel" },
			{ L"xlw", L"application/vnd.ms-excel" },
			{ L"xlw", L"application/x-excel" },
			{ L"xlw", L"application/x-msexcel" },
			{ L"xm", L"audio/xm" },
			{ L"xml", L"application/xml" },
			{ L"xml", L"text/xml" },
			{ L"xmz", L"xgl/movie" },
			{ L"xpix", L"application/x-vnd.ls-xpix" },
			{ L"xpm", L"image/x-xpixmap" },
			{ L"xpm", L"image/xpm" },
			{ L"x-png", L"image/png" },
			{ L"xsr", L"video/x-amt-showrun" },
			{ L"xwd", L"image/x-xwd" },
			{ L"xwd", L"image/x-xwindowdump" },
			{ L"xyz", L"chemical/x-pdb" },
			{ L"z", L"application/x-compress" },
			{ L"z", L"application/x-compressed" },
			{ L"zip", L"application/x-compressed" },
			{ L"zip", L"application/x-zip-compressed" },
			{ L"zip", L"application/zip" },
			{ L"zip", L"multipart/x-zip" },
			{ L"zoo", L"application/octet-stream" },
			{ L"zsh", L"text/x-script.zsh" },
			{ L"", L"" }
		} {}

		HttpServer::HttpServer(const std::wstring & ConfigFile) : DefaultRoute{ L"/{Path}", ContentServer() } {
			auto Config = PVX::IO::LoadJson(ConfigFile.c_str());

			if (auto it = Config.Has(L"Mime"); it)
				for (auto & [Key, Value] : it->Object)
					Mime[Key] = Value.String;

			if (auto it = Config.Has(L"ContentDir"); it)
				SetDefaultRoute(ContentServer(it->String));

			if (auto it = Config.Has(L"ResponseHeader"); it)
				for (auto & Value : it->Object)
					DefaultHeader.push_back({ Value.first, Value.second.String });
		}

		HttpServer::~HttpServer() {}

		std::wstring MakeRegex(const std::wstring & url) {
			return L"^" + regex_replace(url, std::wregex(LR"regex(\{[^\s\{]*\})regex"), LR"regex(([^\s\?]*))regex") + LR"regex((\?(\S*))?)regex";
		}
		std::wstring MakeRegex2(const std::wstring & url) {
			return regex_replace(url, std::wregex(LR"regex(\{[^\s\{]*\})regex"), LR"regex(\{([\S]*)\})regex");
		}

		std::string ToLower(const std::string & s) {
			std::string ret;
			ret.resize(s.size());
			std::transform(s.begin(), s.end(), ret.begin(), [](wchar_t c) { return c | ('a'^'A'); });
			return ret;
		}

		Route::Route(const std::wstring & url, std::function<void(HttpRequest&, HttpResponse&)> action) : Matcher(MakeRegex(url), std::regex_constants::optimize | std::regex_constants::icase | std::regex_constants::ECMAScript), Action(action) {
			OriginalRoute = url;
			std::wregex r(MakeRegex2(url));
			std::wsmatch m;
			if (std::regex_search(url, m, r))
				for (auto i = 1; i < m.size(); i++)
					Names.push_back(m[i].str());
		}

		int Route::Match(const std::wstring & url, std::map<std::wstring, UtfHelper> & Vars, UtfHelper & Query) {
			std::wsmatch m;
			if (std::regex_search(url, m, Matcher) && m.suffix() == L"" && m.size() >= Names.size() + 1) {
				for (auto i = 0; i < Names.size(); i++)
					Vars[Names[i]] = PVX::Decode::Uri(m[i + 1].str());

				if (m.size() == Names.size() + 3)
					Query = m[m.size() - 1].str();

				return 1;
			}
			return 0;
		}

		int Route::Run(HttpRequest &rq, HttpResponse & rsp) throw() {
			Action(rq, rsp);
			return 0;
		}

		void Route::ResetAction(std::function<void(HttpRequest&, HttpResponse&)> action) {
			Action = action;
		}

		int GetRequest(TcpSocket& s, HttpRequest& http, std::vector<uchar>& Content) {
			int EoH = -1;
			http.Socket = s;
			while (s.Receive(http.RawHeader) > 0 &&
				(EoH = http.RawHeader.find("\r\n\r\n")) == -1);
			if (EoH != -1) {
				size_t contentLength = 0;
				size_t sz = EoH + 4;

				if (http.RawHeader.size() > sz) {
					Content.resize(http.RawHeader.size() - sz);
					memcpy(&Content[0], &http.RawHeader[EoH + 4], Content.size());
				}
				http.RawHeader.resize(sz);

				http = http.RawHeader;
				auto cc = http.Headers.find("content-length");
				if (cc != http.Headers.end()) {
					contentLength = _wtoi(cc->second->c_str());
					Content.reserve(contentLength);

					while (Content.size() < contentLength && s.Receive(Content) > 0);
				}
				return contentLength == Content.size();
			}
			return 0;
		}


		//int GetRequest(TcpSocket & s, HttpRequest & http, std::vector<uchar> & Content) {
		//	int EoH = -1;
		//	while (s.Receive(http.RawHeader) > 0 &&
		//		(EoH = http.RawHeader.find("\r\n\r\n")) == -1);
		//	if (EoH != -1) {
		//		size_t contentLength = 0;
		//		size_t sz = EoH + 4;

		//		if (http.RawHeader.size() > sz) {
		//			Content.resize(http.RawHeader.size() - sz);
		//			memcpy(&Content[0], &http.RawHeader[EoH + 4], Content.size());
		//		}
		//		http.RawHeader.resize(sz);

		//		http = http.RawHeader;
		//		auto cc = http.Headers.find("content-length");
		//		if (cc != http.Headers.end()) {
		//			contentLength = _wtoi(cc->second->c_str());
		//			Content.reserve(contentLength);

		//			while (Content.size() < contentLength && s.Receive(Content) > 0);
		//		}
		//		return contentLength == Content.size();
		//	}
		//	return 0;
		//}
		void HttpServer::Routes(const Route & r) {
			Router.push_back(r);
		}
		void HttpServer::Routes(const std::wstring & Url, std::function<void(HttpRequest&, HttpResponse&)> Action) {
			auto url = Url;
			if (url.front() != L'/')url = L"/" + url;
			Router.push_back({ url, Action });
		}
		void HttpServer::Routes(const std::initializer_list<Route>& routes) {
			for (auto & r : routes) {
				Router.push_back(r);
			}
		}

		void HttpServer::SetDefaultRoute(std::function<void(HttpRequest&, HttpResponse&)> Action) {
			DefaultRoute.ResetAction(Action);
		}

		void HttpServer::Start() {}

		void HttpServer::Stop() {}




		WebSocketServer & HttpServer::CreateWebSocketServer(const std::wstring & url) {
			auto Url = url;
			if (Url.front() != L'/') Url = L"/" + url;

			WebSocketServers.push_back(std::make_unique<WebSocketServer>());
			auto ret = WebSocketServers.back().get();

			Routes(Url + L".js", ret->GetScriptHandler(Url));
			Routes(Url, ret->GetHandler());
			ret->ServingThread.push_back(std::thread([ret]() {
				for(;;) {
					if (ret->Connections.size()) {
						for (auto & [connectionId, Socket] : ret->Connections) {

							auto res = Socket.Receive();
							if (res < 0 || Socket.Opcode == WebSocket::Opcode_Close) {
								ret->CloseConnection(connectionId);
								break;
							} else if (res > 0) {
								int type = Socket.Message[0];
								std::string Name;
								size_t sz;
								for (sz = 1; sz < Socket.Message.size() && Socket.Message[sz] != ':'; sz++) Name.push_back(Socket.Message[sz]);
								if (ret->ClientActions.count(Name)) {
									if (type == 'j') {
										JSON::Item params = JSON::jsElementType::Null;
										if (Socket.Message.size() - sz - 1)
											params = PVX::JSON::parse(&Socket.Message[sz + 1], Socket.Message.size() - sz - 1);

										ret->ClientActions[Name](params, connectionId);
									} else if (type == 'b') {
										std::vector<unsigned char> data(Socket.Message.size() - sz - 1);
										memcpy(&data[0], &Socket.Message[sz + 1], Socket.Message.size() - sz - 1);
										ret->ClientActionsRaw[Name](data, connectionId);
									}
								}
							}
						}
					} else {
						std::this_thread::sleep_for(1ms);
					}
				}
			}));
			return *ret;
		}

		const std::wstring & HttpServer::GetMime(const std::wstring & extension) const {
			auto f = Mime.find(extension);
			if (f != Mime.end())
				return f->second;
			return Mime.at(L"");
		}

		std::function<void(HttpRequest&, HttpResponse&)> HttpServer::ContentServer(const std::wstring & ContentPath) {
			std::wstring cPath = PVX::IO::wCurrentPath() + ContentPath + ((ContentPath.size() && (ContentPath.back() == L'\\')) ? L"" : L"\\");
			return [this, cPath](HttpRequest & req, HttpResponse& resp) {
				std::wstring path = cPath + std::regex_replace((std::wstring&)req.Variables[L"Path"], std::wregex(L"/"), L"\\");
				if ((resp.StatusCode = resp.Content.BinaryFile(path.c_str())) == 200) {
#ifdef _DEBUG
					printf("Serving File: %ws\n", path.c_str());
#endif
					std::wsmatch Extension;
					std::map<std::wstring, std::wstring>::iterator pMime;
					if (std::regex_search(path, Extension, std::wregex(L"\\.([^\\.]*)")) && Extension[1].matched && (pMime = Mime.find(Extension[1].str())) != Mime.end()) {
						resp[L"Content-Type"] = pMime->second;
					}
				}
			};
		}

		Route HttpServer::ContentPathRoute(const std::wstring & Url, const std::wstring & Path) {
			auto url = Url;
			if (url.front() != L'/')url = L"/" + url;
			return{ url + L"/{Path}", ContentServer(Path) };
		}

		void HttpServer::DefaultRouteForContent(const std::wstring & Path) {
			SetDefaultRoute(ContentServer(Path));
		}

		std::wstring HttpServer::MakeSession() {
			auto now = std::chrono::system_clock::now().time_since_epoch().count();
			auto sid = (std::wstringstream() << now).str();
			Sessions.insert(sid);
			return sid;
		}

		std::wstring HttpServer::StartSession(PVX::Network::HttpRequest & req, PVX::Network::HttpResponse & resp) {
			if (!req.Cookies.count(L"sid") || !Sessions.count(req.Cookies.at(L"sid"))) {
				auto sid = MakeSession();
				resp.ClearCookie(L"sid");
				resp.SetCookie(L"sid", sid);
				req.Cookies[L"sid"] = sid;
				return req.SessionId = sid;
			}
			return req.SessionId = req.Cookies.at(L"sid");
		}


		int CompressContent(PVX_DataBuilder & Content) {
			Content.SetData(PVX::Compress::Deflate(Content.GetDataVector()));
			return 1;
		}
		static void CompressContent(HttpRequest & http, HttpResponse & r) {
			if (r.Content.GetLength() && http.SouldCompress() && CompressContent(r.Content))
				r[L"Content-Encoding"] = L"deflate";
		}



		int HttpServer::SendResponse(TcpSocket& Socket, HttpRequest & http, HttpResponse& resp) {
			if (resp.SouldCompress) 
				CompressContent(http, resp);
	
			auto ContentLength = resp.Content.GetLength();
			for (auto & s : resp.Streams) 
				ContentLength += s.Size;


			resp.SendHeader(ContentLength);

			//PVX_DataBuilder Response;
			//Response << StatusCodes[resp.StatusCode];
			//resp.Headers[L"date"] = GetDate();


			//if (ContentLength) {
			//	wchar_t tmp[128];
			//	_ui64tow_s(ContentLength, tmp, 128, 10);
			//	resp.Headers[L"content-length"] = tmp;
			//}

			//for (auto & h : resp.Headers)
			//	Response << h.first << ": " << h.second << "\r\n";

			//for(auto & h : resp.MoreHeaders)
			//	Response << h.Name << ": " << h.Value << "\r\n";

			//Response << "\r\n";


			//if (Socket.Send(Response.GetDataVector()) < 0)return 1;
			if (resp.Content.GetLength() && Socket.SendFragmented(resp.Content.GetDataVector()) < resp.Content.GetLength()) return 1;
			for (auto & s : resp.Streams) {
				while (s.Func(Socket));
			}

			return 1;
		}

		void HttpServer::SetDefaultHeader(HttpResponse & http) {
			http.Server = this;
			for (auto h : DefaultHeader)
				http[h.Name] = h.Value;
		}

		void HttpServer::AddFilter(std::function<int(HttpRequest&, HttpResponse&)> Filter) {
			Filters.push_back(Filter);
		}
		std::function<void(TcpSocket)> HttpServer::GetHandler() {
			return [this](TcpSocket Socket) {
				HttpRequest Request;
				while (GetRequest(Socket, Request, Request.RawContent)) {
					//if (Request.Method=="OPTIONS") {
					//	HttpResponse r;
					//	r.StatusCode = 405;
					//	SendResponse(Socket, Request, r);
					//}

					for (auto & r : Router) {
						if (r.Match(Request.QueryString, Request.Variables, Request.Get)) {
							HandleRequest(Socket, Request, r);
							return;
						}
					}

					if (DefaultRoute.Match(Request.QueryString, Request.Variables, Request.Get)) {
						HandleRequest(Socket, Request, DefaultRoute);
						return;
					}

					HttpResponse r;
					r.StatusCode = 500;
					SendResponse(Socket, Request, r);
				}
			};
		}
	}
}