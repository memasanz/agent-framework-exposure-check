require 'fileutils'
require 'json'
require 'minitest/autorun'
require 'open3'
require 'tmpdir'

class MacScannerTest < Minitest::Test
  REPO = File.expand_path('..', __dir__)
  SCANNER = File.join(REPO, 'Test-AgentFrameworkExposure.sh')

  def setup
    @tmp = File.realpath(Dir.mktmpdir('af-scanner-test-'))
    @home = File.join(@tmp, 'home')
    @scope = File.join(@home, 'scope')
    FileUtils.mkdir_p(@scope)
    @sequence = 0
  end

  def teardown
    FileUtils.remove_entry_secure(@tmp)
  end

  def write(path, content = 'inert fixture')
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, content)
    path
  end

  def scan(mode: 'Quick', roots: [@scope], scanner: SCANNER, env: {})
    @sequence += 1
    report = File.join(@tmp, "result-#{@sequence}.json")
    args = ['/bin/bash', scanner, '--mode', mode, '--report', report]
    roots.each { |root| args.concat(['--root', root]) }
    output, status = Open3.capture2e({ 'HOME' => @home }.merge(env), *args)
    assert File.file?(report), output
    html = report.sub(/\.json$/, '.html')
    assert File.file?(html), output
    data = JSON.parse(File.read(report))
    assert_equal data.fetch('ExitCode'), status.exitstatus, output
    [data, File.read(html), output, report]
  end

  def test_quick_includes_git_and_checks_symlink_names_without_following_targets
    git_hook = write(File.join(@scope, '.git', 'af_runtime_diag.pth'))
    outside = File.join(@tmp, 'outside')
    write(File.join(outside, 'af_runtime_diag.py'))
    link = File.join(@scope, 'agent_framework_meta.pth')
    File.symlink(outside, link)
    broken = File.join(@scope, 'af_runtime_diag.pth')
    File.symlink(File.join(@tmp, 'missing'), broken)

    data, html = scan
    assert_equal [git_hook, link, broken].sort, data.fetch('Findings').map { |f| f.fetch('Path') }.sort
    assert_equal 'IndicatorsFound', data.fetch('FindingStatus')
    assert_equal 'Incomplete', data.fetch('CoverageStatus')
    assert_equal 4, data.fetch('ExitCode')
    assert_equal 1, data.fetch('CandidateFilesExamined')
    assert_equal %w[Directory Unavailable], data.fetch('Symlinks').map { |s| s.fetch('TargetType') }.sort
    assert_includes html, 'symlink name only; target not inspected'
  end

  def test_deep_shares_all_four_indicator_checks_with_archives
    archive_root = File.join(@tmp, 'archive')
    entries = %w[agent_framework_meta.pth af_runtime_diag.pth af_runtime_diag.py agent_framework_meta/_telemetry.py]
    entries.each { |entry| write(File.join(archive_root, entry)) }
    write(File.join(archive_root, 'agent_framework-1.26.2.dist-info', 'METADATA'),
          "Name: agent-framework\nVersion: 1.26.2\n")
    archive = File.join(@scope, 'cached.whl')
    output, status = Open3.capture2e('/usr/bin/zip', '-qr', archive, '.', chdir: archive_root)
    assert status.success?, output
    metadata = write(File.join(@scope, 'agent_framework-1.26.1.dist-info', 'METADATA'),
                     "Name: agent-framework\nVersion: 1.26.1\n")
    dependency = write(File.join(@scope, 'requirements.txt'), "agent-framework==1.26.2\n")
    write(File.join(@scope, 'agent_framework_core-1.26.0.dist-info', 'METADATA'),
          "Name: agent-framework-core\nVersion: 1.26.0\n")

    data, = scan(mode: 'Deep')
    assert_equal 'Complete', data.fetch('CoverageStatus')
    assert_equal 3, data.fetch('ExitCode')
    assert_empty data.fetch('Errors')
    archived = data.fetch('Findings').select { |f| f.fetch('LocationType') == 'Archive' }
    assert_equal 5, archived.length
    assert_equal 2, archived.count { |f| f.fetch('Kind') == 'CachedHelperModule' }
    entries.each { |entry| assert archived.any? { |f| f.fetch('Path') == "#{archive}::#{entry}" } }
    assert data.fetch('Findings').any? { |f| f.fetch('Path') == metadata && f.fetch('Kind') == 'PackageOnDisk' }
    assert data.fetch('Findings').any? { |f| f.fetch('Path') == dependency && f.fetch('Kind') == 'DependencyReference' }
  end

  def test_quick_does_not_inspect_package_contents
    write(File.join(@scope, 'agent_framework-1.26.1.dist-info', 'METADATA'),
          "Name: agent-framework\nVersion: 1.26.1\n")
    write(File.join(@scope, 'requirements.txt'), "agent-framework==1.26.2\n")
    data, = scan
    assert_empty data.fetch('Findings')
    assert_equal 'Complete', data.fetch('CoverageStatus')
    assert_equal 0, data.fetch('ExitCode')
    assert_equal 0, data.fetch('CandidateFilesExamined')
  end

  def test_invalid_root_does_not_abort_remaining_roots
    write(File.join(@scope, 'af_runtime_diag.py'))
    data, = scan(roots: [File.join(@tmp, 'absent'), @scope])
    assert_equal 4, data.fetch('ExitCode')
    assert_equal ['InvalidRoot'], data.fetch('Errors').map { |e| e.fetch('Category') }
    assert_equal 1, data.fetch('Findings').length
    assert_equal 2, data.fetch('RequestedRoots').length
    assert_equal [File.realpath(@scope)], data.fetch('Roots')
  end

  def test_symlink_root_with_trailing_slashes_is_not_traversed
    link = File.join(@tmp, 'alias')
    File.symlink(@scope, link)
    write(File.join(@scope, 'af_runtime_diag.py'))
    data, = scan(roots: ["#{link}///"])
    assert_empty data.fetch('Roots')
    assert_empty data.fetch('Findings')
    assert_equal [link], data.fetch('SkippedSymlinks')
    assert_equal 2, data.fetch('ExitCode')
  end

  def test_preflight_does_not_probe_a_sibling_with_a_shared_name_prefix
    @home = "#{@scope}-sibling"
    FileUtils.mkdir_p(File.join(@home, 'Desktop'))
    data, = scan
    assert_equal [@scope], data.fetch('AccessPreflight').map { |p| p.fetch('Path') }
  end

  def test_escaped_paths_and_complete_link_inventory_with_bounded_html
    unusual = File.join(@scope, "quoted\"\\\t\n<script>&-\u00e9")
    FileUtils.mkdir_p(unusual)
    hook = write(File.join(unusual, 'af_runtime_diag.py'))
    25.times { |i| File.symlink(hook, File.join(@scope, "link-#{i}")) }
    data, html = scan
    assert_equal hook, data.fetch('Findings').first.fetch('Path')
    assert_equal 25, data.fetch('SkippedSymlinks').length
    assert_equal 25, data.fetch('Symlinks').length
    assert_includes html, '&lt;script&gt;&amp;'
    refute_includes html, '<script>'
    assert_operator html.scan(/<li>/).length, :<, 30
  end

  def test_access_denial_has_actual_path_and_no_duplicate_find_error
    blocked = File.join(@scope, 'blocked')
    FileUtils.mkdir_p(blocked)
    File.chmod(0, blocked)
    data, html = scan
    error = data.fetch('Errors').fetch(0)
    assert_equal 1, data.fetch('Errors').length
    assert_equal blocked, error.fetch('Path')
    assert_equal 'AccessDenied', error.fetch('Category')
    assert_equal 1, data.fetch('UnresolvedErrorCount')
    assert_equal 2, data.fetch('ExitCode')
    assert_includes html, 'Access denied: 1'
    assert_equal 1, data.fetch('DirectorySearches').fetch(0).fetch('ExitCode')
  ensure
    File.chmod(0700, blocked) if blocked
  end

  def scanner_with_find_fixture
    bin = File.join(@tmp, 'bin')
    FileUtils.mkdir_p(bin)
    find = write(File.join(bin, 'find'), <<~'SH')
      #!/bin/bash
      case " $* " in
          *" -print0 "*)
              if [[ "$1" == "$TEST_SCAN_ROOT" ]]; then
                  case "$TEST_FIND_FAILURE" in
                      silent) exit 7 ;;
                      interrupted)
                          if [[ ! -e "$TEST_FIND_MARKER" ]]; then
                              : > "$TEST_FIND_MARKER"
                              printf '%s\0' "$TEST_PARTIAL_CANDIDATE"
                              printf 'find: fts_read: Interrupted system call\n' >&2
                              exit 1
                          fi
                          ;;
                      interrupted-always)
                          printf 'find: fts_read: Interrupted system call\n' >&2
                          exit 1
                          ;;
                      *) printf 'find: %s: No such file or directory\n' "$TEST_RETRY_PATH" >&2; exit 1 ;;
                  esac
              fi
              if [[ "${TEST_FIND_FAILURE:-}" == retry-failed ]]; then
                  printf 'find: %s: Permission denied\n' "$1" >&2
                  exit 1
              fi
              ;;
      esac
      exec /usr/bin/find "$@"
    SH
    File.chmod(0700, find)
    # Fault injection is confined to a private test copy; production keeps its fixed PATH.
    scanner = write(File.join(@tmp, 'scanner.sh'),
                    File.read(SCANNER).sub('export PATH=/usr/bin:/bin:/usr/sbin:/sbin',
                                          "export PATH=#{bin}:/usr/bin:/bin:/usr/sbin:/sbin"))
    [scanner, { 'TEST_SCAN_ROOT' => @scope }]
  end

  def test_disappeared_subtree_is_retried_once_and_findings_are_preserved
    subtree = File.join(@scope, 'rediscovered')
    hook = write(File.join(subtree, 'af_runtime_diag.pth'))
    scanner, env = scanner_with_find_fixture
    data, = scan(scanner: scanner,
                 env: env.merge('TEST_FIND_FAILURE' => 'retry', 'TEST_RETRY_PATH' => subtree))
    assert_equal 3, data.fetch('ExitCode')
    assert_equal 'Complete', data.fetch('CoverageStatus')
    assert_equal [hook], data.fetch('Findings').map { |f| f.fetch('Path') }
    error = data.fetch('Errors').fetch(0)
    assert_equal subtree, error.fetch('Path')
    assert_equal 'Disappeared', error.fetch('Category')
    assert_equal 'SubtreeRescanned', error.fetch('RetryOutcome')
    assert_equal true, error.fetch('Resolved')
    assert_equal 0, data.fetch('UnresolvedErrorCount')
    assert_equal [false, true], data.fetch('DirectorySearches').map { |s| s.fetch('Retry') }
  end

  def test_failed_or_still_missing_retry_remains_a_coverage_gap
    subtree = File.join(@scope, 'retry-fails')
    FileUtils.mkdir_p(subtree)
    scanner, env = scanner_with_find_fixture
    data, = scan(scanner: scanner,
                 env: env.merge('TEST_FIND_FAILURE' => 'retry-failed', 'TEST_RETRY_PATH' => subtree))
    assert_equal 2, data.fetch('ExitCode')
    assert_equal 'RetryFailed', data.fetch('Errors').fetch(0).fetch('RetryOutcome')
    assert_includes data.fetch('Errors').fetch(0).fetch('Detail'), 'Permission denied'
    assert_equal false, data.fetch('Errors').fetch(0).fetch('Resolved')
    assert_equal 2, data.fetch('DirectorySearches').length

    data, = scan(scanner: scanner,
                 env: env.merge('TEST_FIND_FAILURE' => 'missing', 'TEST_RETRY_PATH' => "#{subtree}/absent"))
    assert_equal 2, data.fetch('ExitCode')
    assert_equal 'StillMissing', data.fetch('Errors').fetch(0).fetch('RetryOutcome')
    assert_equal 1, data.fetch('DirectorySearches').length
  end

  def test_retry_cannot_expand_scope_through_a_diagnostic_or_symlink_ancestor
    outside = File.join(@tmp, 'outside')
    write(File.join(outside, 'af_runtime_diag.py'))
    alias_path = File.join(@scope, 'alias')
    File.symlink(outside, alias_path)
    scanner, env = scanner_with_find_fixture
    [outside, File.join(alias_path, 'af_runtime_diag.py')].each do |path|
      data, = scan(scanner: scanner,
                   env: env.merge('TEST_FIND_FAILURE' => 'retry', 'TEST_RETRY_PATH' => path))
      assert_equal 2, data.fetch('ExitCode')
      assert_empty data.fetch('Findings')
      assert_equal 'OutsideScopeOrUnverifiable', data.fetch('Errors').fetch(0).fetch('RetryOutcome')
      assert_equal 1, data.fetch('DirectorySearches').length
    end
  end

  def test_rediscovered_file_is_selected_using_the_original_mode_rules
    file = write(File.join(@scope, 'requirements.txt'), "agent-framework==1.26.2\n")
    scanner, env = scanner_with_find_fixture
    env = env.merge('TEST_FIND_FAILURE' => 'retry', 'TEST_RETRY_PATH' => file)
    quick, = scan(scanner: scanner, env: env)
    assert_equal 0, quick.fetch('ExitCode')
    assert_equal 0, quick.fetch('CandidateFilesExamined')
    assert_equal 'EntryRescanned', quick.fetch('Errors').fetch(0).fetch('RetryOutcome')
    deep, = scan(scanner: scanner, mode: 'Deep', env: env)
    assert_equal 3, deep.fetch('ExitCode')
    assert_equal [file], deep.fetch('Findings').map { |f| f.fetch('Path') }
  end

  def test_retry_respects_the_original_filesystem_boundary
    subtree = File.join(@scope, 'different-device')
    write(File.join(subtree, 'af_runtime_diag.py'))
    scanner, env = scanner_with_find_fixture
    stat = write(File.join(@tmp, 'bin', 'stat'), <<~'SH')
      #!/bin/bash
      if [[ "$3" == "$TEST_RETRY_PATH" ]]; then printf '2\n'; else printf '1\n'; fi
    SH
    File.chmod(0700, stat)
    data, = scan(scanner: scanner,
                 env: env.merge('TEST_FIND_FAILURE' => 'retry', 'TEST_RETRY_PATH' => subtree))
    assert_equal 2, data.fetch('ExitCode')
    assert_empty data.fetch('Findings')
    assert_equal 'OutsideScopeOrUnverifiable', data.fetch('Errors').fetch(0).fetch('RetryOutcome')
    assert_equal 1, data.fetch('DirectorySearches').length
  end

  def test_interrupted_enumeration_is_retried_once_without_losing_partial_findings
    hook = write(File.join(@scope, 'af_runtime_diag.py'))
    scanner, env = scanner_with_find_fixture
    data, = scan(scanner: scanner,
                 env: env.merge('TEST_FIND_FAILURE' => 'interrupted',
                                'TEST_FIND_MARKER' => File.join(@tmp, 'find-attempted'),
                                'TEST_PARTIAL_CANDIDATE' => hook))
    assert_equal 3, data.fetch('ExitCode')
    assert_equal 'Complete', data.fetch('CoverageStatus')
    assert_equal [hook], data.fetch('Findings').map { |f| f.fetch('Path') }
    assert_equal 2, data.fetch('CandidateFilesExamined')
    assert_equal [false, true], data.fetch('DirectorySearches').map { |s| s.fetch('Retry') }
    error = data.fetch('Errors').fetch(0)
    assert_equal 'Interrupted', error.fetch('Category')
    assert_equal 'RootReenumerated', error.fetch('RetryOutcome')
    assert_equal true, error.fetch('Resolved')
  end

  def test_repeated_interruption_is_bounded_and_remains_incomplete
    scanner, env = scanner_with_find_fixture
    data, = scan(scanner: scanner, env: env.merge('TEST_FIND_FAILURE' => 'interrupted-always'))
    assert_equal 2, data.fetch('ExitCode')
    assert_equal 'Incomplete', data.fetch('CoverageStatus')
    assert_equal 2, data.fetch('DirectorySearches').length
    assert_equal %w[RetryInterrupted RetryLimitReached],
                 data.fetch('Errors').map { |e| e.fetch('RetryOutcome') }.sort
    assert_equal 2, data.fetch('UnresolvedErrorCount')
  end

  def test_search_failure_without_stderr_is_not_silently_successful
    scanner, env = scanner_with_find_fixture
    data, = scan(scanner: scanner, env: env.merge('TEST_FIND_FAILURE' => 'silent'))
    assert_equal 2, data.fetch('ExitCode')
    assert_equal ['TraversalFailure'], data.fetch('Errors').map { |e| e.fetch('Category') }
    assert_equal 7, data.fetch('DirectorySearches').fetch(0).fetch('ExitCode')
  end

  def test_bounded_inspection_reports_limits_instead_of_sigpipe_failure
    write(File.join(@scope, 'requirements.txt'), '#' * (8 * 1024 * 1024 + 1))
    archive_root = File.join(@tmp, 'oversized')
    write(File.join(archive_root, 'agent_framework-1.26.2.dist-info', 'METADATA'),
          "Name: agent-framework\nVersion: 1.26.2\n" + 'X' * (2 * 1024 * 1024))
    output, status = Open3.capture2e('/usr/bin/zip', '-qr', File.join(@scope, 'oversized.whl'),
                                    '.', chdir: archive_root)
    assert status.success?, output
    data, = scan(mode: 'Deep')
    assert_equal 2, data.fetch('ExitCode')
    assert_equal %w[InspectionLimit InspectionLimit], data.fetch('Errors').map { |e| e.fetch('Category') }
    assert data.fetch('Errors').any? { |e| e.fetch('Detail').include?('1 MiB') }
    assert data.fetch('Errors').any? { |e| e.fetch('Detail').include?('8 MiB') }
  end

  def test_launchers_distinguish_incomplete_reports_from_fatal_failure
    distribution = File.join(@tmp, 'distribution')
    %w[Run-QuickScan.command Run-FullScan.command].each do |launcher|
      FileUtils.mkdir_p(distribution)
      FileUtils.cp(File.join(REPO, launcher), distribution)
    end
    stub = File.join(distribution, 'Test-AgentFrameworkExposure.sh')
    { 0 => nil, 1 => 'ERROR:', 2 => 'WARNING:', 3 => 'ALERT:', 4 => 'ALERT:' }.each do |code, label|
      write(stub, "#!/bin/bash\nexit #{code}\n")
      %w[Run-QuickScan.command Run-FullScan.command].each do |launcher|
        output, status = Open3.capture2e({ 'HOME' => @home }, '/bin/bash',
                                        File.join(distribution, launcher), stdin_data: "FULL\n\n")
        assert_equal code, status.exitstatus, output
        assert_includes output, label if label
        refute_includes output, 'ERROR:' if [0, 2, 3, 4].include?(code)
      end
    end
    output, status = Open3.capture2e({ 'HOME' => @home }, '/bin/bash',
                                    File.join(distribution, 'Run-FullScan.command'), stdin_data: "NO\n\n")
    assert status.success?, output
    assert_includes output, 'No scan was started'
  end

  def test_existing_reports_are_not_overwritten
    _, html, _, report = scan
    original = File.read(report)
    output, status = Open3.capture2e({ 'HOME' => @home }, '/bin/bash', SCANNER,
                                    '--root', @scope, '--report', report)
    assert_equal 1, status.exitstatus, output
    assert_equal original, File.read(report)
    assert_equal html, File.read(report.sub(/\.json$/, '.html'))
  end
end
