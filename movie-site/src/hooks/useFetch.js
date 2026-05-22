
import { useState, useEffect, useCallback, useRef } from 'react';

/**
 * Custom hook for fetching data with loading/error states.
 * Automatically cancels requests on unmount to prevent memory leaks.
 *
 * @param {Function} fetchFn - Async function that returns data
 * @param {Array} deps - Dependency array for refetching
 * @param {Object} options - Optional configuration
 * @param {boolean} options.immediate - Whether to fetch on mount (default: true)
 * @returns {{ data, loading, error, refetch }}
 */
export function useFetch(fetchFn, deps = [], { immediate = true } = {}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(immediate);
  const [error, setError] = useState(null);
  const cancelRef = useRef(false);
  const fetchFnRef = useRef(fetchFn);

  // Keep fetchFn ref current without triggering re-renders
  useEffect(() => {
    fetchFnRef.current = fetchFn;
  }, [fetchFn]);

  const execute = useCallback(async () => {
    cancelRef.current = false;
    setLoading(true);
    setError(null);

    try {
      const result = await fetchFnRef.current();
      if (!cancelRef.current) {
        setData(result);
      }
    } catch (err) {
      if (!cancelRef.current) {
        setError(err.message || 'An unexpected error occurred');
      }
    } finally {
      if (!cancelRef.current) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    if (immediate) {
      execute();
    }
    return () => {
      cancelRef.current = true;
    };
  }, deps);

  return { data, loading, error, refetch: execute };
}
