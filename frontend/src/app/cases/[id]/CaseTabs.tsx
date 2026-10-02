import React from "react";
import OverviewTab from "./OverviewTab";
import ReportsTab from "./ReportsTab";
import StaticTab from "./StaticTab";
import DynamicTab from "./DynamicTab";
import C2Tab from "./C2Tab";
import VulnsTab from "./VulnsTab";

interface CaseTabsProps {
  activeTab: string;
  caseData: any;
  phaseStatus: any;
  caseReports: any[];
  analysisResults?: any;
}

export default function CaseTabs({
  activeTab,
  caseData,
  phaseStatus,
  caseReports,
  analysisResults,
}: CaseTabsProps) {
  const isMockCase = false;

  return (
    <div className="flex-1 min-h-0">
      {activeTab === "overview" && (
        <OverviewTab caseData={caseData} phaseStatus={phaseStatus} analysisResults={analysisResults} />
      )}

      {activeTab === "static" && (
        <StaticTab caseData={caseData} analysisResults={analysisResults} isMockCase={isMockCase} />
      )}

      {activeTab === "dynamic" && (
        <DynamicTab caseData={caseData} analysisResults={analysisResults} isMockCase={isMockCase} />
      )}

      {activeTab === "c2" && (
        <C2Tab caseData={caseData} analysisResults={analysisResults} isMockCase={isMockCase} />
      )}

      {activeTab === "vulns" && (
        <VulnsTab caseData={caseData} analysisResults={analysisResults} isMockCase={isMockCase} />
      )}

      {activeTab === "reports" && (
        <ReportsTab caseData={caseData} caseReports={caseReports} analysisResults={analysisResults} />
      )}
    </div>
  );
}
