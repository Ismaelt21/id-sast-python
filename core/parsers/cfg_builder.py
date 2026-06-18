import networkx as nx


class CFGBuilder:

    """
    Control Flow Graph Builder.

    Construye CFG desde AST normalizado.
    """

    def __init__(self):

        self.graph = nx.DiGraph()

        self.node_counter = 0

        self.previous_node = None

    # =========================================================
    # MAIN
    # =========================================================

    def build(self, ast_data: dict):

        self.graph.clear()

        self.node_counter = 0

        self.previous_node = None

        # -----------------------------------------------------
        # ENTRY
        # -----------------------------------------------------

        entry = self._new_node(
            "ENTRY",
            "entry"
        )

        self.previous_node = entry

        # -----------------------------------------------------
        # ASSIGNMENTS
        # -----------------------------------------------------

        for assignment in ast_data.get(
            "assignments",
            []
        ):

            self._handle_assignment(
                assignment
            )

        # -----------------------------------------------------
        # FUNCTION CALLS
        # -----------------------------------------------------

        for call in ast_data.get(
            "calls",
            []
        ):

            self._handle_call(call)

        # -----------------------------------------------------
        # IFS
        # -----------------------------------------------------

        for if_node in ast_data.get(
            "ifs",
            []
        ):

            self._handle_if(if_node)

        # -----------------------------------------------------
        # FORS
        # -----------------------------------------------------

        for for_node in ast_data.get(
            "fors",
            []
        ):

            self._handle_for(for_node)

        # -----------------------------------------------------
        # WHILES
        # -----------------------------------------------------

        for while_node in ast_data.get(
            "whiles",
            []
        ):

            self._handle_while(while_node)

        # -----------------------------------------------------
        # RETURNS
        # -----------------------------------------------------

        for return_node in ast_data.get(
            "returns",
            []
        ):

            self._handle_return(
                return_node
            )

        # -----------------------------------------------------
        # EXIT
        # -----------------------------------------------------

        exit_node = self._new_node(
            "EXIT",
            "exit"
        )

        self._connect(
            self.previous_node,
            exit_node
        )

        return {
            "nodes": self._serialize_nodes(),
            "edges": self._serialize_edges()
        }

    # =========================================================
    # ASSIGNMENTS
    # =========================================================

    def _handle_assignment(
        self,
        assignment
    ):

        label = (
            f"{assignment['target']} = "
            f"{assignment['value']}"
        )

        node = self._new_node(
            label,
            "assignment"
        )

        self._connect(
            self.previous_node,
            node
        )

        self.previous_node = node

    # =========================================================
    # CALLS
    # =========================================================

    def _handle_call(self, call):

        label = call["name"]

        node = self._new_node(
            label,
            "function_call"
        )

        self._connect(
            self.previous_node,
            node
        )

        self.previous_node = node

    # =========================================================
    # IF
    # =========================================================

    def _handle_if(self, if_data):

        node = self._new_node(
            f"IF {if_data['condition']}",
            "if"
        )

        self._connect(
            self.previous_node,
            node
        )

        self.previous_node = node

    # =========================================================
    # FOR
    # =========================================================

    def _handle_for(self, for_data):

        node = self._new_node(
            "FOR_LOOP",
            "loop"
        )

        self._connect(
            self.previous_node,
            node
        )

        self.previous_node = node

    # =========================================================
    # WHILE
    # =========================================================

    def _handle_while(self, while_data):

        node = self._new_node(
            "WHILE_LOOP",
            "loop"
        )

        self._connect(
            self.previous_node,
            node
        )

        self.previous_node = node

    # =========================================================
    # RETURN
    # =========================================================

    def _handle_return(
        self,
        return_data
    ):

        node = self._new_node(
            "RETURN",
            "return"
        )

        self._connect(
            self.previous_node,
            node
        )

        self.previous_node = node

    # =========================================================
    # NODE CREATION
    # =========================================================

    def _new_node(
        self,
        label,
        node_type
    ):

        node_id = f"N{self.node_counter}"

        self.node_counter += 1

        self.graph.add_node(
            node_id,
            label=label,
            type=node_type
        )

        return node_id

    # =========================================================
    # EDGE CREATION
    # =========================================================

    def _connect(
        self,
        source,
        target
    ):

        if source and target:

            self.graph.add_edge(
                source,
                target
            )

    # =========================================================
    # SERIALIZATION
    # =========================================================

    def _serialize_nodes(self):

        return [

            {
                "id": node,
                "label": attrs.get(
                    "label"
                ),
                "type": attrs.get(
                    "type"
                )
            }

            for node, attrs
            in self.graph.nodes(data=True)
        ]

    def _serialize_edges(self):

        return [

            {
                "source": source,
                "target": target
            }

            for source, target
            in self.graph.edges()
        ]