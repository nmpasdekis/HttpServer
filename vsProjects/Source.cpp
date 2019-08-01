#include <PVX_Network.h>
#include <PVX.inl>

using namespace PVX::Network;

int main() {
	int test[]{ 1, 2, 3, 4 };
	auto tst = PVX::ToVector(test, 4);

	TcpServer ServerSocket("8080");
	HttpServer Http;

	Http.Routes(L"/api/test", [](HttpRequest& req, HttpResponse & resp) {
		resp.Json({ { L"Message", "OK" } });
	});

	Http.CreateWebSocketServer(L"ws");

	ServerSocket.Serve(Http.GetHandler());

	getchar();

	return 0;
}