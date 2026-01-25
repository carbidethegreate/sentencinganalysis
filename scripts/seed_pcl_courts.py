from __future__ import annotations

from app import create_app
from pcl_courts_seed import load_pcl_courts_catalog, seed_pcl_courts


def main() -> None:
    app = create_app()
    courts = load_pcl_courts_catalog()
    stats = seed_pcl_courts(app.engine, app.pcl_tables["pcl_courts"], courts)
    print(
        "Seeded PCL courts:",
        f"inserted={stats['inserted']}",
        f"updated={stats['updated']}",
        f"skipped={stats['skipped']}",
    )


if __name__ == "__main__":
    main()
