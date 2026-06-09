from unittest.mock import MagicMock, patch
import pytest
from output.db_writer import DBWriter
from models import Verdict


def _make_verdict():
    return Verdict(
        timestamp="2026-06-09T10:00:00Z",
        source_ip="1.2.3.4",
        user_identity="alice",
        method="POST",
        path="/login",
        classification="FRAUDULENT",
        confidence_score=0.9,
        reason="sql_injection",
        original_log_entry_reference='{"raw":"entry"}',
    )


def _make_writer(mock_connect):
    """Helper: build a DBWriter with a mocked psycopg2 connection."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cursor
    mock_connect.return_value = mock_conn
    writer = DBWriter(db_host="localhost", db_port=5432, db_name="test", db_user="u", db_pass="p")
    return writer, mock_conn, mock_cursor


@patch("output.db_writer.psycopg2.connect")
def test_insert_verdict_executes_insert_into_fraud_verdicts(mock_connect):
    writer, mock_conn, mock_cursor = _make_writer(mock_connect)
    writer.insert_verdict(_make_verdict())
    assert mock_cursor.execute.called
    sql = mock_cursor.execute.call_args[0][0]
    assert "fraud_verdicts" in sql
    mock_conn.commit.assert_called_once()


@patch("output.db_writer.psycopg2.connect")
def test_insert_verdict_passes_correct_fields(mock_connect):
    writer, mock_conn, mock_cursor = _make_writer(mock_connect)
    v = _make_verdict()
    writer.insert_verdict(v)
    params = mock_cursor.execute.call_args[0][1]
    assert params[0] == v.source_ip
    assert params[1] == v.user_identity
    assert params[2] == v.method
    assert params[3] == v.path
    assert params[4] == v.confidence_score
    assert params[5] == v.reason
    assert params[6] == v.original_log_entry_reference


@patch("output.db_writer.psycopg2.connect")
def test_insert_verdict_does_not_raise_on_execute_error(mock_connect):
    writer, mock_conn, mock_cursor = _make_writer(mock_connect)
    mock_cursor.execute.side_effect = Exception("DB error")
    # Must not raise
    writer.insert_verdict(_make_verdict())


@patch("output.db_writer.psycopg2.connect")
def test_db_writer_disables_gracefully_on_connect_failure(mock_connect):
    mock_connect.side_effect = Exception("connection refused")
    writer = DBWriter(db_host="bad", db_port=5432, db_name="test", db_user="u", db_pass="p")
    # Must not raise even with no connection
    writer.insert_verdict(_make_verdict())


@patch("output.db_writer.psycopg2.connect")
def test_close_closes_connection(mock_connect):
    writer, mock_conn, _ = _make_writer(mock_connect)
    writer.close()
    mock_conn.close.assert_called_once()
