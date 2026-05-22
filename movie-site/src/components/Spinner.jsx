
import './Spinner.css';

export default function Spinner({ size = 40, text = 'Loading...' }) {
  return (
    <div className="spinner-container" role="status" aria-label={text}>
      <div
        className="spinner"
        style={{ width: size, height: size }}
      />
      {text && <p className="spinner-text">{text}</p>}
    </div>
  );
}
