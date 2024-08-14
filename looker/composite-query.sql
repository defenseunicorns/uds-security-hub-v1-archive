WITH
    PackageInfo AS (
        SELECT
            p.id AS package_id,
            p.name AS full_name,
            SPLIT_PART (
                p.name,
                '/',
                ARRAY_LENGTH (STRING_TO_ARRAY (p.name, '/'), 1)
            ) AS package_name,
            CASE
                WHEN p.tag LIKE '%upstream%' THEN 'Upstream'
                WHEN p.tag LIKE '%registry1%' THEN 'Registry1'
                WHEN p.tag LIKE '%unicorn%' THEN 'Unicorn'
                ELSE 'Other'
            END AS tag_category
        FROM
            packages p
        WHERE
            p.tag LIKE '%upstream%'
            OR p.tag LIKE '%registry1%'
            OR p.tag LIKE '%unicorn%'
    ),
    LatestScans AS (
        SELECT
            pi.package_id,
            pi.package_name,
            pi.tag_category,
            MAX(s.created_at) AS latest_scan_date
        FROM
            PackageInfo pi
            LEFT JOIN scans s ON pi.package_id = s.package_id
        GROUP BY
            pi.package_id,
            pi.package_name,
            pi.tag_category
    ),
    MaxPackageIds AS (
        SELECT DISTINCT
            ON (package_name, tag_category) pi.package_id,
            pi.package_name,
            pi.tag_category,
            ls.latest_scan_date
        FROM
            PackageInfo pi
            LEFT JOIN LatestScans ls ON pi.package_id = ls.package_id
        ORDER BY
            package_name,
            tag_category,
            ls.latest_scan_date DESC NULLS LAST
    ),
    VulnCounts AS (
        SELECT
            mpi.package_name,
            mpi.tag_category,
            COALESCE(
                COUNT(
                    CASE
                        WHEN v.severity = 'HIGH' THEN 1
                    END
                ),
                0
            ) AS high_vulnerability_count,
            COALESCE(
                COUNT(
                    CASE
                        WHEN v.severity = 'CRITICAL' THEN 1
                    END
                ),
                0
            ) AS critical_vulnerability_count
        FROM
            MaxPackageIds mpi
            LEFT JOIN scans s ON mpi.package_id = s.package_id
            AND s.created_at = mpi.latest_scan_date
            LEFT JOIN vulnerabilities v ON s.id = v.scan_id
            AND v.severity IN ('HIGH', 'CRITICAL')
        GROUP BY
            mpi.package_name,
            mpi.tag_category
    )
SELECT
    vc.package_name,
    vc.tag_category,
    mpi.latest_scan_date,
    vc.high_vulnerability_count,
    vc.critical_vulnerability_count,
    vc.high_vulnerability_count + vc.critical_vulnerability_count AS total_high_critical_vulnerability_count
FROM
    VulnCounts vc
    JOIN MaxPackageIds mpi ON vc.package_name = mpi.package_name
    AND vc.tag_category = mpi.tag_category
ORDER BY
    vc.package_name,
    vc.tag_category;
