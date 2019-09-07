#include <PVX_Network.h>
#include <PVX.inl>
#include <PVX_Encode.h>

using namespace PVX::Network;

int main() {
	TcpServer ServerSocket("8080");
	HttpServer Http;

	Http.Routes(L"/api/{action}", [](HttpRequest& req, HttpResponse & resp) {
		resp.Json({ 
			{ L"Message", req[L"action"] } 
		});
	});

	Http.CreateWebSocketServer(L"ws");

	ServerSocket.Serve(Http.GetHandler());

	getchar();

	return 0;
}