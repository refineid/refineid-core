-- Replaces each ASCII diagram that follows a `<!-- figure: name -->`
-- comment with the typst drawing diagrams/name.typ, and drops the
-- document's own title block, which main.typ sets.
local pending = nil

function RawBlock(el)
  if el.format == "html" then
    local name = el.text:match("<!%-%-%s*figure:%s*([%w%-]+)%s*%-%->")
    if name then
      pending = name
      return {}
    end
  end
end

function CodeBlock(el)
  if pending then
    local name = pending
    pending = nil
    return pandoc.RawBlock("typst",
      '#align(center, block(breakable: false, include "../diagrams/' .. name .. '.typ"))')
  end
end

-- Wide tables: the generated state-by-event and transition tables get
-- fixed column widths, and identifiers inside any table may break after
-- an underscore, so no cell runs into its neighbour or past the margin.
local zwsp = utf8.char(0x200B)

local function breakable(s)
  return (s:gsub("_", "_" .. zwsp))
end

local function header_text(tbl)
  local row = tbl.head.rows[1]
  if not row then return {} end
  local names = {}
  for i, cell in ipairs(row.cells) do
    names[i] = pandoc.utils.stringify(cell.contents)
  end
  return names
end

local function widths_for(names)
  local n = #names
  if names[1] == "Event" and n >= 5 then
    local first = 0.2
    local rest = (1 - first) / (n - 1)
    local w = { first }
    for i = 2, n do w[i] = rest end
    return w
  end
  if names[1] == "From" and names[5] == "Actions" then
    return { 0.17, 0.2, 0.22, 0.13, 0.28 }
  end
  return nil
end

function Table(tbl)
  local widths = widths_for(header_text(tbl))
  if widths then
    for i, spec in ipairs(tbl.colspecs) do
      tbl.colspecs[i] = { spec[1], widths[i] }
    end
  end
  return tbl:walk({
    Str = function(el) return pandoc.Str(breakable(el.text)) end,
    Code = function(el) return pandoc.Code(breakable(el.text), el.attr) end,
  })
end
