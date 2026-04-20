package ghidrassist.graphrag.extraction;

import ghidra.util.Msg;

import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.ChatMessage;
import ghidrassist.apiprovider.exceptions.APIProviderException;
import ghidrassist.graphrag.BinaryKnowledgeGraph;
import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.graphrag.nodes.NodeType;
import ghidrassist.LlmApi;
import ghidrassist.core.ResponseProcessor;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * LLM-powered semantic extraction for the knowledge graph.
 *
 * Handles:
 * - Function summarization with security focus
 * - Batch processing with rate limiting
 * - Embedding generation (when available)
 * - Module/community summarization
 *
 * Uses a tiered approach:
 * 1. If embeddings are available, generate them
 * 2. Generate LLM summaries in batches
 * 3. Track progress and allow cancellation
 */
@SuppressWarnings("deprecation")  // Uses legacy extractSecurityNotes() for backward compatibility
public class SemanticExtractor {

    private final APIProvider provider;
    private final BinaryKnowledgeGraph graph;
    private final ResponseProcessor responseProcessor = new ResponseProcessor();
    @SuppressWarnings("unused")  // Reserved for future multi-binary support
    private final String binaryId;
    private final String systemPrompt;

    // Parallel processing workers
    private static final int PARALLEL_WORKERS = 3;

    // Rate limiting (legacy - kept for compatibility)
    private static final int DEFAULT_BATCH_SIZE = 5;
    private static final long DEFAULT_DELAY_MS = 500;
    @SuppressWarnings("unused")  // Legacy field kept for API compatibility
    private int batchSize;
    @SuppressWarnings("unused")  // Legacy field kept for API compatibility
    private long delayBetweenBatches;

    // Thread-safe statistics
    private AtomicInteger summarized = new AtomicInteger(0);
    private AtomicInteger embeddingsGenerated = new AtomicInteger(0);
    private AtomicInteger errors = new AtomicInteger(0);
    private AtomicInteger processed = new AtomicInteger(0);

    // Cancellation
    private volatile boolean cancelled = false;
    private ExecutorService executor;

    /**
     * Create a SemanticExtractor.
     *
     * @param provider LLM provider for summarization
     * @param graph    Knowledge graph to update
     */
    public SemanticExtractor(APIProvider provider, BinaryKnowledgeGraph graph) {
        this(provider, graph, "You are a binary analysis assistant. Provide concise, technical summaries focused on functionality and security.");
    }

    public SemanticExtractor(APIProvider provider, BinaryKnowledgeGraph graph, String systemPrompt) {
        this.provider = provider;
        this.graph = graph;
        this.binaryId = graph.getBinaryId();
        this.systemPrompt = (systemPrompt != null && !systemPrompt.isBlank())
            ? systemPrompt
            : "You are a binary analysis assistant. Provide concise, technical summaries focused on functionality and security.";
        this.batchSize = DEFAULT_BATCH_SIZE;
        this.delayBetweenBatches = DEFAULT_DELAY_MS;
    }

    /**
     * Configure batch processing parameters.
     */
    public void setBatchConfig(int batchSize, long delayMs) {
        this.batchSize = Math.max(1, batchSize);
        this.delayBetweenBatches = Math.max(0, delayMs);
    }

    /**
     * Process all stale nodes that need summarization.
     *
     * @param limit Maximum number of nodes to process (0 = unlimited)
     * @param progressCallback Optional callback for progress updates
     * @return ExtractionResult with statistics
     */
    public ExtractionResult summarizeStaleNodes(int limit, ProgressCallback progressCallback) {
        long startTime = System.currentTimeMillis();
        cancelled = false;
        summarized.set(0);
        embeddingsGenerated.set(0);
        errors.set(0);
        processed.set(0);

        // Get stale nodes
        List<KnowledgeNode> staleNodes = graph.getStaleNodes(limit > 0 ? limit : Integer.MAX_VALUE);
        int total = staleNodes.size();

        if (total == 0) {
            Msg.info(this, "No stale nodes to summarize");
            return new ExtractionResult(0, 0, 0, 0);
        }

        Msg.info(this, "Starting summarization of " + total + " stale nodes");

        // Log first few node addresses for debugging
        if (total > 0) {
            StringBuilder firstNodes = new StringBuilder("First 10 nodes to process: ");
            for (int i = 0; i < Math.min(10, total); i++) {
                KnowledgeNode n = staleNodes.get(i);
                firstNodes.append(String.format("%s(0x%s) ",
                    n.getName(),
                    n.getAddress() != null ? Long.toHexString(n.getAddress()) : "EXT"));
            }
            Msg.info(this, firstNodes.toString());
        }

        // Process nodes with parallel workers
        try {
            provider.prepareForConcurrentRequests();
        } catch (APIProviderException e) {
            Msg.error(this, "Failed to prepare provider for concurrent semantic requests: " + e.getMessage(), e);
            errors.incrementAndGet();
            long elapsed = System.currentTimeMillis() - startTime;
            return new ExtractionResult(summarized.get(), embeddingsGenerated.get(), errors.get(), elapsed);
        }
        Msg.info(this, "Using " + PARALLEL_WORKERS + " parallel workers");
        ExecutorService executor = Executors.newFixedThreadPool(PARALLEL_WORKERS);

        // Track active futures for cancellation
        List<Future<?>> activeFutures = new ArrayList<>();
        int submitted = 0;

        try {
            for (KnowledgeNode node : staleNodes) {
                // Check for cancellation before submitting new work
                if (cancelled) {
                    Msg.info(this, "Cancellation requested, stopping submission after " + submitted + " tasks");
                    break;
                }

                final KnowledgeNode nodeToProcess = node;
                Future<?> future = executor.submit(() -> {
                    try {
                        if (nodeToProcess.getType() == NodeType.FUNCTION) {
                            processSingleFunctionParallel(nodeToProcess);
                        } else {
                            // Log non-function nodes for debugging
                            Msg.info(this, "Processing non-FUNCTION node: " + nodeToProcess.getName() +
                                " (type=" + nodeToProcess.getType() + ", addr=" +
                                (nodeToProcess.getAddress() != null ? "0x" + Long.toHexString(nodeToProcess.getAddress()) : "null") + ")");
                            processOtherNodeParallel(nodeToProcess);
                        }
                    } catch (Exception e) {
                        Msg.warn(this, "Error processing node " + nodeToProcess.getName() + ": " + e.getMessage());
                        errors.incrementAndGet();
                    } finally {
                        // Update progress
                        int currentProcessed = processed.incrementAndGet();
                        if (progressCallback != null) {
                            progressCallback.onProgress(currentProcessed, total, summarized.get(), errors.get());
                        }
                    }
                });
                activeFutures.add(future);
                submitted++;

                // Limit outstanding tasks to avoid memory issues
                // Wait for some tasks to complete if we have too many pending
                while (activeFutures.size() >= PARALLEL_WORKERS * 2 && !cancelled) {
                    // Remove completed futures
                    activeFutures.removeIf(Future::isDone);
                    if (activeFutures.size() >= PARALLEL_WORKERS * 2) {
                        Thread.sleep(100);
                    }
                }
            }

            // Wait for remaining tasks to complete
            Msg.info(this, "Waiting for " + activeFutures.size() + " remaining tasks to complete...");
            while (!activeFutures.isEmpty() && !cancelled) {
                activeFutures.removeIf(Future::isDone);
                if (!activeFutures.isEmpty()) {
                    Thread.sleep(100);
                }
            }

            if (cancelled) {
                Msg.info(this, "Cancellation detected, cancelling remaining futures");
                for (Future<?> f : activeFutures) {
                    f.cancel(true);
                }
            }
        } catch (InterruptedException e) {
            Msg.warn(this, "Interrupted during processing: " + e.getMessage());
            Thread.currentThread().interrupt();
        } finally {
            executor.shutdownNow();
            try {
                executor.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        long elapsed = System.currentTimeMillis() - startTime;
        Msg.info(this, String.format("Parallel semantic extraction completed in %dms: %d summarized, %d embeddings, %d errors",
                elapsed, summarized.get(), embeddingsGenerated.get(), errors.get()));

        return new ExtractionResult(summarized.get(), embeddingsGenerated.get(), errors.get(), elapsed);
    }

    /**
     * Summarize a single node on-demand.
     * For FUNCTION nodes, uses the full detailed prompt with context.
     */
    public boolean summarizeNode(KnowledgeNode node) {
        Msg.info(this, "summarizeNode called for: " + (node != null ? node.getName() : "null"));

        if (node == null) {
            Msg.warn(this, "summarizeNode: node is null");
            return false;
        }
        if (node.getRawContent() == null || node.getRawContent().isEmpty()) {
            Msg.warn(this, "summarizeNode: rawContent is null or empty for node " + node.getName());
            return false;
        }

        Msg.info(this, "summarizeNode: rawContent length = " + node.getRawContent().length());

        try {
            String response;

            // For FUNCTION nodes, use the full detailed prompt with context
            if (node.getType() == NodeType.FUNCTION) {
                // Get context (callers/callees) if graph is available
                List<String> callers = new ArrayList<>();
                List<String> callees = new ArrayList<>();

                if (graph != null) {
                    callers = graph.getCallers(node.getId()).stream()
                            .map(n -> n.getName() != null ? n.getName() : "unknown")
                            .limit(5)
                            .collect(Collectors.toList());

                    callees = graph.getCallees(node.getId()).stream()
                            .map(n -> n.getName() != null ? n.getName() : "unknown")
                            .limit(5)
                            .collect(Collectors.toList());
                }

                // Generate full detailed prompt
                String prompt = ExtractionPrompts.functionSummaryPrompt(
                        node.getName() != null ? node.getName() : "unknown",
                        node.getRawContent(),
                        callers,
                        callees
                );

                Msg.info(this, "summarizeNode: calling LLM with detailed function prompt...");
                response = callLLM(prompt);

                if (response != null && !response.isEmpty()) {
                    node.setLlmSummary(response);
                    node.setConfidence(0.85f);

                    String category = ExtractionPrompts.extractCategory(response);
                    if (category != null && !category.isEmpty()) {
                        node.setCategory(category);
                    }
                }
            } else {
                // For non-FUNCTION nodes, use the generic summary
                Msg.info(this, "summarizeNode: calling generateSummary for non-function node...");
                response = generateSummary(node);

                if (response != null && !response.isEmpty()) {
                    node.setLlmSummary(response);
                    node.setConfidence(0.7f);
                }
            }

            Msg.info(this, "summarizeNode: LLM returned " +
                    (response != null ? response.length() + " chars" : "null"));

            if (response != null && !response.isEmpty()) {
                node.markUpdated();

                // Try to generate embedding
                tryGenerateEmbedding(node);

                graph.upsertNode(node);
                Msg.info(this, "summarizeNode: success");
                return true;
            } else {
                Msg.warn(this, "summarizeNode: LLM returned null or empty response");
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to summarize node " + node.getId() + ": " + e.getMessage(), e);
        }
        return false;
    }

    /**
     * Cancel ongoing extraction.
     */
    public void cancel() {
        cancelled = true;
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    // ========================================
    // Parallel Processing Methods (thread-safe)
    // ========================================

    /**
     * Process a single function in parallel (thread-safe version).
     */
    private void processSingleFunctionParallel(KnowledgeNode node) {
        try {
            // Skip external functions - they have no function body to summarize
            if (node.getAddress() == null) {
                Msg.info(this, "Skipping external function (no body): " + node.getName());
                return;
            }

            // Skip functions without raw content
            if (node.getRawContent() == null || node.getRawContent().isEmpty()) {
                Msg.info(this, "Skipping function with no raw content: " + node.getName() +
                    " (addr=0x" + Long.toHexString(node.getAddress()) + ")");
                return;
            }

            Msg.info(this, "Processing function: " + node.getName() + " (id=" + node.getId() + ")");

            // Get context (callers/callees)
            List<String> callers = graph.getCallers(node.getId()).stream()
                    .map(n -> n.getName() != null ? n.getName() : "unknown")
                    .limit(5)
                    .collect(Collectors.toList());

            List<String> callees = graph.getCallees(node.getId()).stream()
                    .map(n -> n.getName() != null ? n.getName() : "unknown")
                    .limit(5)
                    .collect(Collectors.toList());

            // Generate prompt
            String prompt = ExtractionPrompts.functionSummaryPrompt(
                    node.getName() != null ? node.getName() : "unknown",
                    node.getRawContent(),
                    callers,
                    callees
            );

            String response = callLLM(prompt);
            if (response != null && !response.isEmpty()) {
                Msg.info(this, "Got response for " + node.getName() + ", length=" + response.length());
                node.setLlmSummary(response);
                node.setConfidence(0.85f);

                String category = ExtractionPrompts.extractCategory(response);
                if (category != null && !category.isEmpty()) {
                    node.setCategory(category);
                }

                node.markUpdated();
                node.setStale(false);
                tryGenerateEmbedding(node);

                Msg.info(this, "Upserting node " + node.getName() + " with summary length=" +
                    (node.getLlmSummary() != null ? node.getLlmSummary().length() : 0));
                graph.upsertNode(node);

                int count = summarized.incrementAndGet();
                Msg.info(this, "Successfully summarized " + node.getName() + " (total: " + count + ")");
            } else {
                Msg.warn(this, "Empty response for " + node.getName());
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to summarize function " + node.getName() + ": " + e.getMessage(), e);
            errors.incrementAndGet();
        }
    }

    /**
     * Process a non-function node in parallel (thread-safe version).
     */
    private void processOtherNodeParallel(KnowledgeNode node) {
        try {
            String summary = generateSummary(node);
            if (summary != null) {
                node.setLlmSummary(summary);
                node.setConfidence(0.7f);
                node.markUpdated();
                tryGenerateEmbedding(node);
                graph.upsertNode(node);
                summarized.incrementAndGet();
            }
        } catch (Exception e) {
            Msg.warn(this, "Failed to summarize node " + node.getId() + ": " + e.getMessage());
            errors.incrementAndGet();
        }
    }

    // ========================================
    // Batch Processing (legacy - kept for compatibility)
    // ========================================

    private void processBatch(List<KnowledgeNode> batch) {
        // Separate by type for appropriate prompts
        List<KnowledgeNode> functions = batch.stream()
                .filter(n -> n.getType() == NodeType.FUNCTION)
                .collect(Collectors.toList());

        List<KnowledgeNode> others = batch.stream()
                .filter(n -> n.getType() != NodeType.FUNCTION)
                .collect(Collectors.toList());

        // Process functions (most common case)
        if (!functions.isEmpty()) {
            processFunctionBatch(functions);
        }

        // Process other node types individually
        for (KnowledgeNode node : others) {
            if (cancelled) break;
            processOtherNode(node);
        }
    }

    private void processFunctionBatch(List<KnowledgeNode> functions) {
        // Process ALL functions individually with the detailed prompt
        // This ensures consistent, high-quality summaries with caller/callee context
        // for both simple and complex functions (same as Explain Function)
        for (KnowledgeNode func : functions) {
            if (cancelled) break;
            processSingleFunction(func);
        }
    }

    private void processSingleFunction(KnowledgeNode node) {
        try {
            // Skip external functions - they have no function body to summarize
            if (node.getAddress() == null) {
                return;
            }

            // Skip functions without raw content
            if (node.getRawContent() == null || node.getRawContent().isEmpty()) {
                return;
            }

            // Get context (callers/callees)
            List<String> callers = graph.getCallers(node.getId()).stream()
                    .map(n -> n.getName() != null ? n.getName() : "unknown")
                    .limit(5)
                    .collect(Collectors.toList());

            List<String> callees = graph.getCallees(node.getId()).stream()
                    .map(n -> n.getName() != null ? n.getName() : "unknown")
                    .limit(5)
                    .collect(Collectors.toList());

            // Generate prompt
            String prompt = ExtractionPrompts.functionSummaryPrompt(
                    node.getName() != null ? node.getName() : "unknown",
                    node.getRawContent(),
                    callers,
                    callees
            );

            String response = callLLM(prompt);
            if (response != null) {
                node.setLlmSummary(response);
                node.setConfidence(0.85f);

                String category = ExtractionPrompts.extractCategory(response);
                if (category != null && !category.isEmpty()) {
                    node.setCategory(category);
                }

                node.markUpdated();
                tryGenerateEmbedding(node);
                graph.upsertNode(node);
                summarized.incrementAndGet();
            }
        } catch (Exception e) {
            Msg.warn(this, "Failed to summarize function " + node.getName() + ": " + e.getMessage());
            errors.incrementAndGet();
        }
    }

    private void processOtherNode(KnowledgeNode node) {
        try {
            String summary = generateSummary(node);
            if (summary != null) {
                node.setLlmSummary(summary);
                node.setConfidence(0.7f);
                node.markUpdated();
                tryGenerateEmbedding(node);
                graph.upsertNode(node);
                summarized.incrementAndGet();
            }
        } catch (Exception e) {
            Msg.warn(this, "Failed to summarize node " + node.getId() + ": " + e.getMessage());
            errors.incrementAndGet();
        }
    }

    private void parseBatchResponse(String response, List<KnowledgeNode> functions) {
        // Parse numbered list response
        String[] lines = response.split("\n");
        int index = 0;

        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty()) continue;

            // Match numbered lines like "1. Summary text" or "1) Summary text"
            if (line.matches("^\\d+[.)].*")) {
                // Extract summary after number
                int pos = line.indexOf(' ');
                if (pos > 0 && index < functions.size()) {
                    String summary = line.substring(pos).trim();
                    if (!summary.isEmpty()) {
                        KnowledgeNode node = functions.get(index);
                        node.setLlmSummary(summary);
                        node.setConfidence(0.75f);
                        node.markUpdated();
                        graph.upsertNode(node);
                        summarized.incrementAndGet();
                    }
                    index++;
                }
            }
        }

        // Log if we didn't match all functions
        if (index < functions.size()) {
            Msg.warn(this, "Batch response only matched " + index + " of " + functions.size() + " functions");
        }
    }

    // ========================================
    // LLM and Embedding Helpers
    // ========================================

    private String generateSummary(KnowledgeNode node) {
        if (node.getRawContent() == null || node.getRawContent().isEmpty()) {
            return null;
        }

        String prompt;
        switch (node.getType()) {
            case FUNCTION:
                prompt = ExtractionPrompts.functionBriefSummaryPrompt(
                        node.getName() != null ? node.getName() : "unknown",
                        node.getRawContent()
                );
                break;
            case BINARY:
                prompt = "Summarize this binary in 2-3 sentences:\n\n" + node.getRawContent();
                break;
            case MODULE:
                prompt = "Summarize this module/component in 1-2 sentences:\n\n" + node.getRawContent();
                break;
            default:
                prompt = "Briefly describe this code:\n\n" + truncate(node.getRawContent(), 1000);
        }

        return callLLM(prompt);
    }

    private String callLLM(String prompt) {
        if (provider == null) {
            Msg.warn(this, "callLLM: No LLM provider available for summarization");
            return null;
        }

        Msg.info(this, "callLLM: calling provider " + provider.getClass().getSimpleName() +
                " with prompt length " + prompt.length());

        try {
            List<ChatMessage> messages = new ArrayList<>();
            messages.add(new ChatMessage("system", systemPrompt));
            messages.add(new ChatMessage("user", prompt));

            String response = provider.createChatCompletion(messages);
            response = responseProcessor.filterThinkBlocks(response);
            Msg.info(this, "callLLM: received response " +
                    (response != null ? response.length() + " chars" : "null"));
            return response;
        } catch (APIProviderException e) {
            Msg.error(this, "callLLM failed: " + e.getMessage(), e);
            return null;
        }
    }

    private void tryGenerateEmbedding(KnowledgeNode node) {
        if (provider == null || node.getLlmSummary() == null) {
            return;
        }

        try {
            double[] embedding = provider.getEmbeddings(node.getLlmSummary());
            if (embedding != null && embedding.length > 0) {
                // Convert double[] to float[]
                float[] floatEmbedding = new float[embedding.length];
                for (int i = 0; i < embedding.length; i++) {
                    floatEmbedding[i] = (float) embedding[i];
                }
                node.setEmbedding(floatEmbedding);
                embeddingsGenerated.incrementAndGet();
            }
        } catch (Exception e) {
            // Embeddings are optional - don't log as error
            Msg.debug(this, "Embedding generation not available: " + e.getMessage());
        }
    }

    private String truncate(String text, int maxLength) {
        if (text == null || text.length() <= maxLength) {
            return text;
        }
        return text.substring(0, maxLength) + "...";
    }

    // ========================================
    // Result and Callback Types
    // ========================================

    /**
     * Results from semantic extraction.
     */
    public static class ExtractionResult {
        public final int summarized;
        public final int embeddingsGenerated;
        public final int errors;
        public final long elapsedMs;

        public ExtractionResult(int summarized, int embeddings, int errors, long elapsed) {
            this.summarized = summarized;
            this.embeddingsGenerated = embeddings;
            this.errors = errors;
            this.elapsedMs = elapsed;
        }

        @Override
        public String toString() {
            return String.format("Summarized %d nodes, %d embeddings, %d errors in %dms",
                    summarized, embeddingsGenerated, errors, elapsedMs);
        }
    }

    /**
     * Callback for progress updates.
     */
    public interface ProgressCallback {
        void onProgress(int processed, int total, int summarized, int errors);
    }

    // ========================================
    // Streaming Summary Support
    // ========================================

    /**
     * Callback interface for streaming summary updates.
     */
    public interface StreamingSummaryCallback {
        /**
         * Called when streaming starts.
         */
        void onStart();

        /**
         * Called when a partial summary is available.
         * @param accumulated The accumulated response so far
         */
        void onPartialSummary(String accumulated);

        /**
         * Called when the summary is complete.
         * @param fullSummary The complete summary
         * @param updatedNode The node with updated summary and metadata
         */
        void onSummaryComplete(String fullSummary, KnowledgeNode updatedNode);

        /**
         * Called when an error occurs.
         * @param error The error that occurred
         */
        void onError(Throwable error);

        /**
         * Called when the LLM enters or exits a thinking block.
         * @param thinking true when entering a think block, false when exiting
         */
        default void onThinkingStateChanged(boolean thinking) {}

        /**
         * Check if streaming should continue.
         * @return true to continue, false to cancel
         */
        default boolean shouldContinue() { return true; }
    }

    /**
     * Summarize a node with streaming updates.
     * Similar to summarizeNode() but calls callback as text arrives.
     *
     * @param node The knowledge node to summarize (must be a FUNCTION node)
     * @param callback The callback to receive streaming updates
     */
    public void summarizeNodeStreaming(KnowledgeNode node, StreamingSummaryCallback callback) {
        if (node == null) {
            callback.onError(new IllegalArgumentException("Node cannot be null"));
            return;
        }

        if (node.getType() != NodeType.FUNCTION) {
            callback.onError(new IllegalArgumentException("Only FUNCTION nodes are supported for streaming summarization"));
            return;
        }

        if (node.getRawContent() == null || node.getRawContent().isEmpty()) {
            callback.onError(new IllegalArgumentException("Node has no raw content to summarize"));
            return;
        }

        // Get context (callers/callees) if graph is available
        List<String> callers = new ArrayList<>();
        List<String> callees = new ArrayList<>();

        if (graph != null) {
            callers = graph.getCallers(node.getId()).stream()
                    .map(n -> n.getName() != null ? n.getName() : "unknown")
                    .limit(5)
                    .collect(Collectors.toList());

            callees = graph.getCallees(node.getId()).stream()
                    .map(n -> n.getName() != null ? n.getName() : "unknown")
                    .limit(5)
                    .collect(Collectors.toList());
        }

        // Generate full detailed prompt
        String prompt = ExtractionPrompts.functionSummaryPrompt(
                node.getName() != null ? node.getName() : "unknown",
                node.getRawContent(),
                callers,
                callees
        );

        callback.onStart();

        // Use streaming LLM call
        callLLMStreaming(prompt, new LlmApi.LlmResponseHandler() {
            // Track accumulated content for streaming updates
            private final StringBuilder accumulated = new StringBuilder();
            // Safe accumulator that never resets - used for final storage
            private final StringBuilder safeAccumulated = new StringBuilder();

            @Override
            public void onStart() {
                // Already called callback.onStart() above
            }

            @Override
            public void onUpdate(String partialResponse) {
                // Extract delta from cumulative response
                String current = accumulated.toString();
                String delta;
                if (partialResponse.startsWith(current)) {
                    delta = partialResponse.substring(current.length());
                    accumulated.append(delta);
                } else {
                    // If provider gives full response each time
                    delta = partialResponse;
                    accumulated.setLength(0);
                    accumulated.append(partialResponse);
                }

                // Always append delta to safe accumulator (never reset)
                if (!delta.isEmpty()) {
                    safeAccumulated.append(delta);
                }

                if (!accumulated.toString().isEmpty()) {
                    callback.onPartialSummary(accumulated.toString());
                }
            }

            @Override
            public void onComplete(String fullResponse) {
                // Prefer fullResponse from provider, then safeAccumulated, then accumulated
                String finalResponse;
                if (fullResponse != null && !fullResponse.isEmpty()) {
                    finalResponse = fullResponse;
                } else if (safeAccumulated.length() > 0) {
                    finalResponse = safeAccumulated.toString();
                } else {
                    finalResponse = accumulated.toString();
                }

                // Update node with response
                extractAndUpdateNode(node, finalResponse);
                node.markUpdated();

                // Try to generate embedding
                tryGenerateEmbedding(node);

                // Save to graph
                graph.upsertNode(node);

                callback.onSummaryComplete(finalResponse, node);
            }

            @Override
            public void onError(Throwable error) {
                callback.onError(error);
            }

            @Override
            public boolean shouldContinue() {
                return callback.shouldContinue();
            }

            @Override
            public void onThinkingStateChanged(boolean thinking) {
                callback.onThinkingStateChanged(thinking);
            }
        });
    }

    /**
     * Make a streaming LLM call.
     *
     * @param prompt The prompt to send
     * @param handler The handler for streaming responses
     */
    private void callLLMStreaming(String prompt, LlmApi.LlmResponseHandler handler) {
        if (provider == null) {
            handler.onError(new IllegalStateException("No LLM provider available for summarization"));
            return;
        }

        try {
            List<ChatMessage> messages = new ArrayList<>();
            messages.add(new ChatMessage("system", systemPrompt));
            messages.add(new ChatMessage("user", prompt));

            // Use streaming API with think-tag filtering
            ResponseProcessor.StreamingResponseFilter filter = responseProcessor.createStreamingFilter();
            provider.streamChatCompletion(messages, new LlmApi.LlmResponseHandler() {
                private boolean wasThinking = false;

                @Override
                public void onStart() { handler.onStart(); }

                @Override
                public void onUpdate(String partialResponse) {
                    String filtered = filter.processChunk(partialResponse);
                    boolean isThinking = filter.isInsideThinkBlock();

                    // Signal thinking state transitions
                    if (isThinking && !wasThinking) {
                        handler.onThinkingStateChanged(true);
                    } else if (!isThinking && wasThinking) {
                        handler.onThinkingStateChanged(false);
                    }
                    wasThinking = isThinking;

                    if (!isThinking && filtered != null && !filtered.isEmpty()) {
                        handler.onUpdate(filtered);
                    }
                }

                @Override
                public void onComplete(String fullResponse) {
                    if (wasThinking) {
                        handler.onThinkingStateChanged(false);
                    }
                    handler.onComplete(filter.getFilteredContent());
                }

                @Override
                public void onError(Throwable error) { handler.onError(error); }

                @Override
                public boolean shouldContinue() { return handler.shouldContinue(); }
            });
        } catch (APIProviderException e) {
            handler.onError(e);
        }
    }

    /**
     * Extract metadata from LLM response and update node.
     * Common logic shared between summarizeNode() and summarizeNodeStreaming().
     *
     * @param node The node to update
     * @param response The LLM response
     */
    private void extractAndUpdateNode(KnowledgeNode node, String response) {
        if (response == null || response.isEmpty()) {
            return;
        }

        node.setLlmSummary(response);
        node.setConfidence(0.85f);

        String category = ExtractionPrompts.extractCategory(response);
        if (category != null && !category.isEmpty()) {
            node.setCategory(category);
        }
    }
}
