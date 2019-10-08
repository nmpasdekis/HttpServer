#include <PVX_Network.h>
#include <PVX.inl>
#include <PVX_Encode.h>
#include <PVX_File.h>

using namespace PVX::Network;

int main() {
	TcpServer ServerSocket("8080");
	HttpServer Http;

	PVX::JSON::Item actions;
	PVX::IO::ChangeEventer Eventer;

	auto& ws = Http.CreateWebSocketServer(L"ws");

	Eventer.Track(L"api.json", [&actions, &ws]() { 
		actions = PVX::IO::LoadJson("api.json");
		ws.RunAll(L"Updated", actions["test"]);
	});

	Http.AddFilter([](HttpRequest& req, HttpResponse& resp) {
		if (req.Method=="OPTIONS") {
			return 0;
		}
		resp.AllowOrigin(req);
		//resp[L"Access-Control-Allow-Credentials"] = L"true";
		//resp[L"Access-Control-Allow-Methods"] = L"GET, POST, PUT, DELETE, OPTIONS";
		//resp[L"Access-Control-Allow-Headers"] = L"Origin, X-Requested-With, Content-Type, Accept, Authorization";
		return 1;
	});

	Http.Routes(L"/api/{action}", [&actions](HttpRequest& req, HttpResponse & resp) {
		if (auto& act = *actions.Has(req[L"action"]); &act) {
			resp.Json(act);
			return;
		}
		resp.StatusCode = 404;
		resp.Html("<h3>Endpoint not found</h3>");
	});
	Http.DefaultRouteForContent(L"\\html");


	ws.AddClientAction("action", [&](auto Arguments, auto ConnectionId) {
		ws.Run(ConnectionId, L"Updated");
	});

	ws.OnConnect([&](auto ConnectionId, auto Socket) {
		printf("%s Connected\n", ConnectionId.c_str());
	});

	ServerSocket.Serve(Http.GetHandler());

	getchar();

	return 0;
}