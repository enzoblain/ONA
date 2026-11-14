import { Link } from "react-router-dom";

export function NotFound() {
  return (
    <div className="lost">
      <div>
        <img src="/logo.png" alt="" width={72} height={72} />
        <h1>Nothing at this address.</h1>
        <p>The page you asked for does not exist.</p>
        <Link className="btn btn-primary" to="/">Back to the home page</Link>
      </div>
    </div>
  );
}
