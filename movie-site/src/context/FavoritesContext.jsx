
import { createContext, useContext, useCallback, useMemo } from 'react';
import { useLocalStorage } from '../hooks/useLocalStorage';

const FavoritesContext = createContext(null);

export function FavoritesProvider({ children }) {
  const [favorites, setFavorites] = useLocalStorage('movie-site-favorites', []);

  const addFavorite = useCallback(
    (movie) => {
      setFavorites((prev) => {
        if (prev.some((fav) => fav.id === movie.id)) return prev;
        // Store minimal movie data needed for display
        const { id, title, poster_path, vote_average, release_date, overview } = movie;
        return [...prev, { id, title, poster_path, vote_average, release_date, overview }];
      });
    },
    [setFavorites]
  );

  const removeFavorite = useCallback(
    (movieId) => {
      setFavorites((prev) => prev.filter((fav) => fav.id !== movieId));
    },
    [setFavorites]
  );

  const isFavorite = useCallback(
    (movieId) => {
      return favorites.some((fav) => fav.id === movieId);
    },
    [favorites]
  );

  const value = useMemo(
    () => ({
      favorites,
      addFavorite,
      removeFavorite,
      isFavorite,
      favoritesCount: favorites.length,
    }),
    [favorites, addFavorite, removeFavorite, isFavorite]
  );

  return (
    <FavoritesContext.Provider value={value}>
      {children}
    </FavoritesContext.Provider>
  );
}

export function useFavorites() {
  const context = useContext(FavoritesContext);
  if (!context) {
    throw new Error('useFavorites must be used within a FavoritesProvider');
  }
  return context;
}
