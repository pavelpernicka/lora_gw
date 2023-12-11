# Find loragw
#
# Find the loragw includes and library
#
# if you need to add a custom library search path, do it via CMAKE_PREFIX_PATH
#
# This module defines
#  LORAGW_INCLUDE_DIRS, where to find header, etc.
#  LORAGW_LIBRARIES, the libraries needed to use loragw.
#  LORAGW_LINK_LIBRARIES, the libraries needed to use loragw.
#  LORAGW_FOUND, If false, do not try to use loragw.

# only look in default directories
find_path(
	LORAGW_INCLUDE_DIR
	NAMES loragw_hal.h # only one of those head files
	PATH_SUFFIXES "libloragw"
	DOC "loragw include dir"
)

find_library(
	LORAGW_LIBRARY
	NAMES loragw libloragw
	DOC "loragw library"
)

set(LORAGW_INCLUDE_DIRS ${LORAGW_INCLUDE_DIR})
set(LORAGW_LIBRARIES ${LORAGW_LIBRARY})
set(LORAGW_LINK_LIBRARIES ${LORAGW_LIBRARY})

# handle the QUIETLY and REQUIRED arguments and set USATCK_FOUND to TRUE
# if all listed variables are TRUE, hide their existence from configuration view
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(loragw DEFAULT_MSG
        LORAGW_LIBRARY LORAGW_INCLUDE_DIR )
mark_as_advanced (LORAGW_INCLUDE_DIR LORAGW_LIBRARY)
