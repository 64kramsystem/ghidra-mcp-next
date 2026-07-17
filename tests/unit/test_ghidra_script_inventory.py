from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "ghidra_scripts"
RETAINED = {
    "ApplyDWORD.java",
    "ArgumentsUnifier.py",
    "BSimBulkQuery.java",
    "BSimIngestProgram.java",
    "BSimQueryFunction.java",
    "BSimTestConnection.java",
    "ClearAllComments.java",
    "ClearAndDisasm.java",
    "ClearCallReturnOverrides.java",
    "ClearFunctionComments.java",
    "ClearPrePostComments.java",
    "ConvertNamespaceToClass.java",
    "CreateFunctionsFromArray.py",
    "DeleteFunctionAt.java",
    "FindFunctionsAfterPadding.java",
    "FindFunctionsAfterPaddingAllPrograms.java",
    "FindFunctionsAtINT3.java",
    "FixIATExternalFunctionAddresses.java",
    "ProperSizeStringsScript.java",
    "RemoveDecompilerComments.java",
    "RemoveOrphanedFunctions.java",
    "RestoreLibraryFunctionNamesFromPlateComments.java",
    "UpgradeAllPrograms.java",
    "namespacer.py",
    "README.md",
}


def test_script_inventory_is_generic_allowlist():
    actual = {path.name for path in SCRIPTS.iterdir() if path.is_file()}
    assert actual == RETAINED


def test_bsim_scripts_have_no_remote_default_or_propagation_language():
    combined = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in SCRIPTS.glob("BSim*.java")
    )
    assert "10.0.10.30" not in combined
    assert "DEFAULT_BSIM_URL" not in combined
    assert "AndPropagate" not in combined
    assert "BSim URL is required" in combined


def test_bsim_url_argument_positions_and_interactive_fallback_are_explicit():
    expected_indexes = {
        "BSimTestConnection.java": 0,
        "BSimIngestProgram.java": 0,
        "BSimBulkQuery.java": 0,
        "BSimQueryFunction.java": 1,
    }
    for filename, index in expected_indexes.items():
        source = (SCRIPTS / filename).read_text(encoding="utf-8", errors="replace")
        assert f'requireBsimUrl(args, {index},' in source
        assert 'catch (IllegalArgumentException e)' in source
        assert 'if (!isRunningHeadless())' in source
        assert 'askString(dialogTitle, "Enter BSim database URL:")' in source
        assert 'throw new IllegalArgumentException("BSim URL is required")' in source


def test_single_function_query_is_read_only_and_named_for_its_behavior():
    source = (SCRIPTS / "BSimQueryFunction.java").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "public class BSimQueryFunction extends GhidraScript" in source
    assert "applying names, comments, or other metadata" in source
    assert "setName(" not in source
    assert "setComment(" not in source


def test_retained_scripts_have_no_application_or_repository_server_workflow():
    combined = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in SCRIPTS.iterdir()
        if path.is_file()
    )
    assert "D2COMMON" not in combined
    assert "Diablo" not in combined
    assert ".checkout(" not in combined
    assert "check in manually" not in combined.lower()
    assert "getSharedProjectURL" not in combined
    for fixed_address in ("00681a48", "6ffb5cb8", "6fccaf41", "6fccb0ff"):
        assert fixed_address not in combined.lower()


def test_address_mutation_scripts_take_context_or_caller_input():
    clear_source = (SCRIPTS / "ClearAndDisasm.java").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "getScriptArgs()" in clear_source
    assert "currentSelection" in clear_source
    assert "askAddress(" in clear_source
    assert "Start and end addresses are required" in clear_source

    delete_source = (SCRIPTS / "DeleteFunctionAt.java").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "getScriptArgs()" in delete_source
    assert "currentAddress" in delete_source
    assert "askAddress(" in delete_source
    assert "Function address is required" in delete_source
