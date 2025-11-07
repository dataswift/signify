defmodule Signify.Application do
  @moduledoc """
  The Signify Application supervisor.

  Starts and supervises the KERI infrastructure components.
  """

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Start the Key Event Log (KEL)
      {Signify.KERI.KEL.Log, [name: Signify.KERI.KEL.Log]}

      # Future components:
      # {Signify.KERI.State.KeyStateCache, []},
      # {Signify.KERI.Witnesses.WitnessPool, []},
      # {Signify.KERI.Multisig.Coordinator, []},
    ]

    opts = [strategy: :one_for_one, name: Signify.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
