
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'https://api.themoviedb.org/3';
const API_KEY = import.meta.env.VITE_API_KEY;

const api = axios.create({
  baseURL: API_BASE,
  params: {
    api_key: API_KEY,
    language: 'en-US',
  },
});

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response) {
      const { status, data } = error.response;
      const message = data?.status_message || `Request failed with status ${status}`;
      console.error(`[API Error] ${status}: ${message}`);
      return Promise.reject(new Error(message));
    } else if (error.request) {
      console.error('[API Error] No response received');
      return Promise.reject(new Error('Network error. Please check your connection.'));
    }
    return Promise.reject(error);
  }
);

// Movie endpoints
export const movieService = {
  getPopular: (page = 1) => api.get('/movie/popular', { params: { page } }),
  getTopRated: (page = 1) => api.get('/movie/top_rated', { params: { page } }),
  getNowPlaying: (page = 1) => api.get('/movie/now_playing', { params: { page } }),
  getUpcoming: (page = 1) => api.get('/movie/upcoming', { params: { page } }),
  getDetails: (movieId) => api.get(`/movie/${movieId}`),
  getCredits: (movieId) => api.get(`/movie/${movieId}/credits`),
  getRecommendations: (movieId) => api.get(`/movie/${movieId}/recommendations`),
  search: (query, page = 1) =>
    api.get('/search/movie', { params: { query, page } }),
  getGenres: () => api.get('/genre/movie/list'),
  getTrending: (timeWindow = 'day') =>
    api.get(`/trending/movie/${timeWindow}`),
};

// Image helper
export const IMAGE_BASE_URL = 'https://image.tmdb.org/t/p';
export const getImageUrl = (path, size = 'w500') =>
  path ? `${IMAGE_BASE_URL}/${size}${path}` : null;
export const getBackdropUrl = (path) =>
  path ? `${IMAGE_BASE_URL}/original${path}` : null;

export default api;
