package v2raysocks_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mtoly/XrayRP/api"
	"github.com/Mtoly/XrayRP/api/v2raysocks"
)

func CreateClient() api.API {
	apiConfig := &api.Config{
		APIHost:  "https://127.0.0.1/",
		Key:      "123456789",
		NodeID:   280002,
		NodeType: "V2ray",
	}
	client := v2raysocks.New(apiConfig)
	return client
}

func TestGetV2rayNodeinfo(t *testing.T) {
	client := CreateClient()
	client.Debug()
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetSSNodeinfo(t *testing.T) {
	apiConfig := &api.Config{
		APIHost:  "https://127.0.0.1/",
		Key:      "123456789",
		NodeID:   280009,
		NodeType: "Shadowsocks",
	}
	client := v2raysocks.New(apiConfig)
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetTrojanNodeinfo(t *testing.T) {
	apiConfig := &api.Config{
		APIHost:  "https://127.0.0.1/",
		Key:      "123456789",
		NodeID:   280008,
		NodeType: "Trojan",
	}
	client := v2raysocks.New(apiConfig)
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetUserList(t *testing.T) {
	client := CreateClient()

	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
	}

	t.Log(userList)
}

func TestReportReportUserTraffic(t *testing.T) {
	client := CreateClient()
	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
	}
	generalUserTraffic := make([]api.UserTraffic, len(*userList))
	for i, userInfo := range *userList {
		generalUserTraffic[i] = api.UserTraffic{
			UID:      userInfo.UID,
			Upload:   114514,
			Download: 114514,
		}
	}
	// client.Debug()
	err = client.ReportUserTraffic(&generalUserTraffic)
	if err != nil {
		t.Error(err)
	}
}

func TestGetNodeRule(t *testing.T) {
	client := CreateClient()
	client.Debug()
	ruleList, err := client.GetNodeRule()
	if err != nil {
		t.Error(err)
	}

	t.Log(ruleList)
}

func TestGetSocksNodeInfoAndUsers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("node_id"); got != "1" {
			t.Errorf("unexpected node_id: %s", got)
		}
		if got := r.URL.Query().Get("token"); got != "secret" {
			t.Errorf("unexpected token: %s", got)
		}

		switch r.URL.Query().Get("act") {
		case "config":
			if got := r.URL.Query().Get("node_type"); got != "socks" {
				t.Errorf("unexpected config node_type: %s", got)
			}
			_, _ = w.Write([]byte(`{"server_port":1080}`))
		case "user":
			if got := r.URL.Query().Get("node_type"); got != "socks" {
				t.Errorf("unexpected user node_type: %s", got)
			}
			_, _ = w.Write([]byte(`{"message":"ok","data":[{"id":72,"password":"C1FFFAEC-739B-4ECF-8121-73A456C93EF7","dt":10,"st":1000},{"id":77,"password":"143EC7E9-590B-479E-A5E4-521E265FB601","dt":10,"st":88}]}`))
		default:
			t.Fatalf("unexpected act: %s", r.URL.Query().Get("act"))
		}
	}))
	defer server.Close()

	client := v2raysocks.New(&api.Config{
		APIHost:  server.URL,
		Key:      "secret",
		NodeID:   1,
		NodeType: "Socks",
	})

	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo failed: %v", err)
	}
	if nodeInfo.NodeType != "Socks" {
		t.Fatalf("unexpected node type: %s", nodeInfo.NodeType)
	}
	if nodeInfo.Port != 1080 {
		t.Fatalf("unexpected port: %d", nodeInfo.Port)
	}
	if nodeInfo.TransportProtocol != "tcp" {
		t.Fatalf("unexpected transport: %s", nodeInfo.TransportProtocol)
	}

	userList, err := client.GetUserList()
	if err != nil {
		t.Fatalf("GetUserList failed: %v", err)
	}
	if len(*userList) != 2 {
		t.Fatalf("unexpected user count: %d", len(*userList))
	}
	if (*userList)[0].UUID != "C1FFFAEC-739B-4ECF-8121-73A456C93EF7" {
		t.Fatalf("unexpected socks credential: %s", (*userList)[0].UUID)
	}
	if (*userList)[0].Email != (*userList)[0].UUID {
		t.Fatalf("expected email to match credential, got %s", (*userList)[0].Email)
	}
	if (*userList)[0].SpeedLimit != 125000000 {
		t.Fatalf("unexpected speed limit: %d", (*userList)[0].SpeedLimit)
	}

	ruleList, err := client.GetNodeRule()
	if err != nil {
		t.Fatalf("GetNodeRule failed: %v", err)
	}
	if len(*ruleList) != 0 {
		t.Fatalf("unexpected rule count: %d", len(*ruleList))
	}
}

func TestGetHTTPNodeInfoAndUsers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("act") {
		case "config":
			if got := r.URL.Query().Get("node_type"); got != "http" {
				t.Errorf("unexpected config node_type: %s", got)
			}
			_, _ = w.Write([]byte(`{"server_port":8080,"tls":1}`))
		case "user":
			if got := r.URL.Query().Get("node_type"); got != "http" {
				t.Errorf("unexpected user node_type: %s", got)
			}
			_, _ = w.Write([]byte(`{"message":"ok","data":[{"id":72,"password":"C1FFFAEC-739B-4ECF-8121-73A456C93EF7","dt":10,"st":1000}]}`))
		default:
			t.Fatalf("unexpected act: %s", r.URL.Query().Get("act"))
		}
	}))
	defer server.Close()

	client := v2raysocks.New(&api.Config{
		APIHost:  server.URL,
		Key:      "secret",
		NodeID:   1,
		NodeType: "HTTP",
	})

	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo failed: %v", err)
	}
	if nodeInfo.NodeType != "HTTP" {
		t.Fatalf("unexpected node type: %s", nodeInfo.NodeType)
	}
	if nodeInfo.Port != 8080 {
		t.Fatalf("unexpected port: %d", nodeInfo.Port)
	}
	if !nodeInfo.EnableTLS {
		t.Fatal("expected HTTP TLS to be enabled")
	}

	userList, err := client.GetUserList()
	if err != nil {
		t.Fatalf("GetUserList failed: %v", err)
	}
	if len(*userList) != 1 {
		t.Fatalf("unexpected user count: %d", len(*userList))
	}
	if (*userList)[0].UUID != "C1FFFAEC-739B-4ECF-8121-73A456C93EF7" {
		t.Fatalf("unexpected http credential: %s", (*userList)[0].UUID)
	}
	if (*userList)[0].Email != (*userList)[0].UUID {
		t.Fatalf("expected email to match credential, got %s", (*userList)[0].Email)
	}
}
