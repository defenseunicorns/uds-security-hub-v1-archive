WITH
  LatestScans AS (
  SELECT
    s.package_id,
    MAX(s.created_at) AS latest_scan_date
  FROM
    scans s
  GROUP BY
    s.package_id )
SELECT
  SPLIT_PART(p.name,
    '/',
    ARRAY_LENGTH(STRING_TO_ARRAY(p.name,
        '/'), 1)) AS package_name,
  COALESCE(SUM(CASE
        WHEN v.severity = 'HIGH' THEN 1
        ELSE 0
    END
      ), 0) AS high_vulnerability_count,
  COALESCE(SUM(CASE
        WHEN v.severity = 'CRITICAL' THEN 1
        ELSE 0
    END
      ), 0) AS critical_vulnerability_count,
  CASE
    WHEN p.tag LIKE '%upstream%' THEN 'Upstream'
    WHEN p.tag LIKE '%registry1%' THEN 'Registry1'
    WHEN p.tag LIKE '%unicorn%' THEN 'Unicorn'
    ELSE 'Other'
END
  AS tag_category
FROM
  packages p
LEFT JOIN
  scans s
ON
  p.id = s.package_id
LEFT JOIN
  vulnerabilities v
ON
  s.id = v.scan_id
  AND v.severity IN ('HIGH',
    'CRITICAL')
LEFT JOIN
  LatestScans ls
ON
  s.package_id = ls.package_id
  AND s.created_at = ls.latest_scan_date
WHERE
  p.tag LIKE '%upstream%'
  OR p.tag LIKE '%registry1%'
  OR p.tag LIKE '%unicorn%'
GROUP BY
  p.name,
  tag_category
ORDER BY
  p.name;