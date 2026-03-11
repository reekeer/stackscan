"""Typed schema for frameworks.json using Pydantic."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class FrameworkEntry(BaseModel):
    name: str
    category: str
    html: list[str] = Field(default_factory=list)
    headers: list[str] = Field(default_factory=list)
    cookies: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class FrameworksDocument(BaseModel):
    schema_url: str = Field(default="", alias="$schema")
    version: str = ""
    frameworks: list[FrameworkEntry] = []

    model_config = ConfigDict(extra="forbid", populate_by_name=True)
