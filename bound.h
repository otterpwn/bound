#pragma once

#ifndef BOUND_H
#define BOUND_H

#include <vector>
#include <string>
#include <Windows.h>

struct NetworkConnection {
    DWORD owningProcess;
    std::wstring localAddress;
    DWORD localPort;
    std::wstring remoteAddress;
    DWORD remotePort;
};

struct Rule {
    std::wstring ruleName;
    std::wstring ruleDescription;
};

BOOL enumConnectionsWMI(IN OUT std::vector<NetworkConnection>& connections);
std::wstring getImageFileName(IN DWORD pid);
std::wstring ipToRange(IN const std::wstring& ip);
Rule getRandomRule(IN std::vector<Rule> rulesVector);
void filterConnections(IN const std::vector<DWORD>& targetPIDs, IN const std::vector<NetworkConnection>& allConnections, IN OUT std::vector<NetworkConnection>& connectionsToBlock);
BOOL filterProcesses(IN const std::vector<std::wstring>& processNames, OUT std::vector<DWORD>& foundPIDs);
BOOL setFWRule(IN const std::wstring& binaryPath, IN const std::wstring& ipRange);

#endif // BOUND_H