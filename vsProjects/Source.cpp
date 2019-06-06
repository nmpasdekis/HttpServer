#include <PVX_Network.h>

using namespace PVX::Network;

int main() {
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