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
	Http.DefaultRouteForContent(L"\\html");

	auto & ws = Http.CreateWebSocketServer(L"ws");

	ws.AddClientAction("action:arg1,arg2", [&](auto Arguments, auto ConnectionId) {
		auto arg1 = Arguments[L"arg1"];
		auto arg2 = Arguments[L"arg2"];

		ws.Run(ConnectionId, L"runme", 123);
	});

	ws.OnConnect([&](auto ConnectionId, auto Socket) {
		printf("%s Connected\n", ConnectionId.c_str());
	});

	ServerSocket.Serve(Http.GetHandler());

	getchar();

	return 0;
}