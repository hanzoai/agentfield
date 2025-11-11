import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  ShieldCheck,
  Renew,
  Terminal,
  Copy,
  Download,
  CheckCircle,
  XCircle,
  ChevronRight,
  ChevronDown,
} from "@/components/ui/icon-bridge";
import { CompactTable } from "@/components/ui/CompactTable";
import { SearchBar } from "@/components/ui/SearchBar";
import { PageHeader } from "../components/PageHeader";
import * as identityApi from "../services/identityApi";
import type { VCSearchResult } from "../services/identityApi";
import { formatRelativeTime } from "../utils/dateFormat";

const ITEMS_PER_PAGE = 50;
const GRID_TEMPLATE = "50px minmax(150px,1fr) minmax(120px,1fr) minmax(150px,1fr) minmax(120px,1fr) 80px";

// Filter options
const TIME_FILTER_OPTIONS = [
  { value: "1h", label: "Last Hour" },
  { value: "24h", label: "Last 24 Hours" },
  { value: "7d", label: "Last 7 Days" },
  { value: "30d", label: "Last 30 Days" },
  { value: "all", label: "All Time" },
];

const VERIFICATION_FILTER_OPTIONS = [
  { value: "all", label: "All" },
  { value: "verified", label: "Verified Only" },
  { value: "failed", label: "Failed Only" },
];

export function CredentialsPage() {
  const navigate = useNavigate();

  // State
  const [credentials, setCredentials] = useState<VCSearchResult[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [timeRange, setTimeRange] = useState("24h");
  const [verificationFilter, setVerificationFilter] = useState("all");
  const [selectedCredential, setSelectedCredential] = useState<VCSearchResult | null>(null);

  // Loading states
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);

  // Pagination
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [total, setTotal] = useState(0);

  const [error, setError] = useState<string | null>(null);
  const [showVCJson, setShowVCJson] = useState(false);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Compute time range for API
  const getTimeRangeParams = useCallback((range: string) => {
    if (range === "all") return {};

    const now = new Date();
    const ranges: Record<string, number> = {
      "1h": 60 * 60 * 1000,
      "24h": 24 * 60 * 60 * 1000,
      "7d": 7 * 24 * 60 * 60 * 1000,
      "30d": 30 * 24 * 60 * 60 * 1000,
    };

    const ms = ranges[range];
    const startTime = new Date(now.getTime() - ms);
    return {
      start_time: startTime.toISOString(),
      end_time: now.toISOString(),
    };
  }, []);

  // Fetch credentials
  const fetchCredentials = useCallback(
    async (newOffset: number = 0, reset: boolean = true) => {
      try {
        if (reset) {
          setLoading(true);
          setError(null);
        } else {
          setLoadingMore(true);
        }

        const timeParams = getTimeRangeParams(timeRange);

        const data = await identityApi.searchCredentials({
          ...timeParams,
          status: verificationFilter === 'all' ? undefined : verificationFilter,
          limit: ITEMS_PER_PAGE,
          offset: newOffset,
        });

        const results = data.credentials || [];

        if (reset) {
          setCredentials(results);
        } else {
          setCredentials((prev) => [...prev, ...results]);
        }

        setTotal(data.total || 0);
        setHasMore((data.total || 0) > newOffset + ITEMS_PER_PAGE);
        setOffset(newOffset);
      } catch (err) {
        console.error("Failed to fetch credentials:", err);
        setError(err instanceof Error ? err.message : "Failed to fetch credentials");
        if (reset) {
          setCredentials([]);
        }
      } finally {
        setLoading(false);
        setLoadingMore(false);
      }
    },
    [timeRange, verificationFilter, getTimeRangeParams]
  );

  // Initial load and filter changes
  useEffect(() => {
    fetchCredentials(0, true);
  }, [fetchCredentials]);

  // Filter credentials by search query and verification status
  const filteredCredentials = credentials.filter((cred) => {
    // Verification filter
    if (verificationFilter === "verified" && !cred.verified) return false;
    if (verificationFilter === "failed" && cred.verified) return false;

    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      return (
        cred.execution_id.toLowerCase().includes(query) ||
        cred.workflow_id.toLowerCase().includes(query) ||
        (cred.issuer_did && cred.issuer_did.toLowerCase().includes(query)) ||
        (cred.agent_name && cred.agent_name.toLowerCase().includes(query))
      );
    }

    return true;
  });

  // Handlers
  const handleRefresh = () => {
    fetchCredentials(0, true);
  };

  const handleLoadMore = () => {
    if (!hasMore || loadingMore) return;
    fetchCredentials(offset + ITEMS_PER_PAGE, false);
  };

  const handleCredentialClick = (credential: VCSearchResult) => {
    setSelectedCredential(credential);
    setShowVCJson(false);
  };

  const handleBackToList = () => {
    setSelectedCredential(null);
    setShowVCJson(false);
  };

  const handleCopy = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedText(label);
      setTimeout(() => setCopiedText(null), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  const handleDownloadVC = (vc: VCSearchResult) => {
    const dataStr = JSON.stringify(vc, null, 2);
    const dataBlob = new Blob([dataStr], { type: "application/json" });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `vc-${vc.execution_id}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleExportFiltered = async () => {
    const dataStr = JSON.stringify(filteredCredentials, null, 2);
    const dataBlob = new Blob([dataStr], { type: "application/json" });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `credentials-export-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  // Table columns
  const columns = [
    {
      key: "verified",
      header: "✓",
      sortable: true,
      align: "center" as const,
      render: (cred: VCSearchResult) => (
        <div className="flex items-center justify-center">
          {cred.verified ? (
            <CheckCircle size={16} className="text-green-600" />
          ) : (
            <XCircle size={16} className="text-red-600" />
          )}
        </div>
      ),
    },
    {
      key: "execution_id",
      header: "Execution ID",
      sortable: false,
      align: "left" as const,
      render: (cred: VCSearchResult) => (
        <div className="flex items-center gap-2 min-w-0">
          <code className="text-xs font-mono text-muted-foreground truncate block">
            {cred.execution_id}
          </code>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 flex-shrink-0"
            onClick={(e) => {
              e.stopPropagation();
              handleCopy(cred.execution_id, "execution");
            }}
          >
            <Copy className="w-3 h-3" />
          </Button>
        </div>
      ),
    },
    {
      key: "agent_name",
      header: "Agent",
      sortable: false,
      align: "left" as const,
      render: (cred: VCSearchResult) => (
        <span className="text-sm text-muted-foreground truncate block">
          {cred.agent_name || "—"}
        </span>
      ),
    },
    {
      key: "workflow_id",
      header: "Workflow",
      sortable: false,
      align: "left" as const,
      render: (cred: VCSearchResult) => (
        <div
          className="text-sm text-primary cursor-pointer hover:underline truncate"
          onClick={(e) => {
            e.stopPropagation();
            navigate(`/workflows/${cred.workflow_id}`);
          }}
        >
          {cred.workflow_id}
        </div>
      ),
    },
    {
      key: "created_at",
      header: "Created",
      sortable: true,
      align: "left" as const,
      render: (cred: VCSearchResult) => (
        <span className="text-sm text-muted-foreground whitespace-nowrap">
          {formatRelativeTime(cred.created_at)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "",
      sortable: false,
      align: "center" as const,
      render: (cred: VCSearchResult) => (
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7"
          onClick={(e) => {
            e.stopPropagation();
            handleDownloadVC(cred);
          }}
          title="Download"
        >
          <Download className="w-3.5 h-3.5" />
        </Button>
      ),
    },
  ];

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-6 overflow-hidden">
      <PageHeader
        title=""
        description={
          selectedCredential
            ? `Viewing credential for execution ${selectedCredential.execution_id}`
            : `Verifiable credentials for agent executions and workflows${total > 0 ? ` • Showing ${filteredCredentials.length} of ${total}` : ""}`
        }
        filters={
          !selectedCredential
            ? [
                {
                  label: "Time Range",
                  value: timeRange,
                  options: TIME_FILTER_OPTIONS,
                  onChange: (value) => setTimeRange(value),
                },
                {
                  label: "Verification",
                  value: verificationFilter,
                  options: VERIFICATION_FILTER_OPTIONS,
                  onChange: (value) => setVerificationFilter(value),
                },
              ]
            : undefined
        }
        aside={
          <div className="flex items-center gap-2">
            {selectedCredential && (
              <Button variant="ghost" size="sm" onClick={handleBackToList}>
                ← Back to Credentials
              </Button>
            )}
            {!selectedCredential && filteredCredentials.length > 0 && (
              <Button
                variant="outline"
                size="sm"
                onClick={handleExportFiltered}
                className="flex items-center gap-2"
              >
                <Download size={14} />
                Export ({filteredCredentials.length})
              </Button>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={handleRefresh}
              disabled={loading}
              className="flex items-center gap-2"
            >
              <Renew size={14} className={loading ? "animate-spin" : ""} />
              Refresh
            </Button>
          </div>
        }
      />

      {/* Error Alert */}
      {error && (
        <Alert variant="destructive">
          <Terminal className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Content */}
      <div className="flex min-h-0 flex-1 flex-col gap-6 overflow-hidden">
        {selectedCredential ? (
          // Credential Detail View
          <>
            <div className="bg-card border border-border rounded-lg p-6">
              <div className="flex items-start justify-between mb-6">
                <div className="flex items-center gap-3">
                  <ShieldCheck size={20} className="text-primary" />
                  <div>
                    <h2 className="text-lg font-semibold">Verifiable Credential</h2>
                    <code className="text-xs text-muted-foreground font-mono mt-1 block">
                      {selectedCredential.execution_id}
                    </code>
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleCopy(JSON.stringify(selectedCredential, null, 2), "json")}
                  >
                    <Copy size={14} className="mr-2" />
                    {copiedText === "json" ? "Copied!" : "Copy JSON"}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleDownloadVC(selectedCredential)}
                  >
                    <Download size={14} className="mr-2" />
                    Download
                  </Button>
                </div>
              </div>

              {/* Details Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                <div className="space-y-3">
                  <h3 className="text-sm font-semibold">Execution Details</h3>
                  <div className="space-y-2 text-sm">
                    {selectedCredential.agent_name && (
                      <div>
                        <span className="text-muted-foreground">Agent:</span>
                        <div className="mt-1">{selectedCredential.agent_name}</div>
                      </div>
                    )}
                    <div>
                      <span className="text-muted-foreground">Workflow:</span>
                      <div
                        className="font-mono text-xs mt-1 text-primary cursor-pointer hover:underline"
                        onClick={() => navigate(`/workflows/${selectedCredential.workflow_id}`)}
                      >
                        {selectedCredential.workflow_id}
                      </div>
                    </div>
                    {selectedCredential.session_id && (
                      <div>
                        <span className="text-muted-foreground">Session:</span>
                        <div className="font-mono text-xs mt-1">{selectedCredential.session_id}</div>
                      </div>
                    )}
                    <div>
                      <span className="text-muted-foreground">Created:</span>
                      <div className="mt-1">
                        {formatRelativeTime(selectedCredential.created_at)}
                      </div>
                    </div>
                  </div>
                </div>

                <div className="space-y-3">
                  <h3 className="text-sm font-semibold">Verification</h3>
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 text-sm">
                      {selectedCredential.verified ? (
                        <>
                          <CheckCircle size={16} className="text-green-600" />
                          <span className="text-green-600 font-medium">Signature Valid</span>
                        </>
                      ) : (
                        <>
                          <XCircle size={16} className="text-red-600" />
                          <span className="text-red-600 font-medium">Not Verified</span>
                        </>
                      )}
                    </div>

                    <div className="space-y-2 text-sm">
                      <div>
                        <span className="text-muted-foreground">Issuer DID:</span>
                        <div className="font-mono text-xs mt-1 break-all">
                          {selectedCredential.issuer_did || "N/A"}
                        </div>
                      </div>

                      <div>
                        <span className="text-muted-foreground">Target DID:</span>
                        <div className="font-mono text-xs mt-1 break-all">
                          {selectedCredential.target_did || "N/A"}
                        </div>
                      </div>

                      {selectedCredential.caller_did && (
                        <div>
                          <span className="text-muted-foreground">Caller DID:</span>
                          <div className="font-mono text-xs mt-1 break-all">
                            {selectedCredential.caller_did}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* VC JSON Document */}
              <div className="border-t border-border pt-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-semibold">W3C JSON-LD Document</h3>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setShowVCJson(!showVCJson)}
                  >
                    {showVCJson ? (
                      <>
                        <ChevronDown size={14} className="mr-1" />
                        Collapse
                      </>
                    ) : (
                      <>
                        <ChevronRight size={14} className="mr-1" />
                        Expand
                      </>
                    )}
                  </Button>
                </div>

                {showVCJson && (
                  <div className="bg-muted rounded-lg p-4 overflow-x-auto">
                    <pre className="text-xs font-mono">
                      {JSON.stringify(selectedCredential, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </>
        ) : (
          // Credentials List View
          <>
            <SearchBar
              value={searchQuery}
              onChange={setSearchQuery}
              placeholder="Search by execution ID, workflow, agent, or issuer DID..."
              wrapperClassName="w-full lg:max-w-md"
            />

            <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
              <CompactTable
                data={filteredCredentials}
                loading={loading}
                hasMore={hasMore}
                isFetchingMore={loadingMore}
                sortBy="created_at"
                sortOrder="desc"
                onSortChange={() => {}}
                onLoadMore={handleLoadMore}
                onRowClick={handleCredentialClick}
                columns={columns}
                gridTemplate={GRID_TEMPLATE}
                emptyState={{
                  title: searchQuery
                    ? "No matching credentials"
                    : timeRange === "all"
                      ? "No credentials found"
                      : `No credentials in ${TIME_FILTER_OPTIONS.find(o => o.value === timeRange)?.label.toLowerCase()}`,
                  description: searchQuery
                    ? "Try adjusting your search terms or filters."
                    : timeRange !== "all"
                      ? "Try expanding the time range to see more credentials."
                      : "Credentials will appear here as executions complete.",
                  icon: <ShieldCheck className="h-6 w-6 text-muted-foreground" />,
                }}
                getRowKey={(cred) => cred.vc_id}
              />
            </div>
          </>
        )}
      </div>
    </div>
  );
}
